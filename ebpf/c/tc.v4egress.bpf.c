// SPDX-License-Identifier: Apache-2.0
// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Derived from: https://github.com/aws/aws-network-policy-agent
// Modified for debugging and educational purposes
// 
// KEY DIFFERENCE FROM INGRESS:
// - This program checks DESTINATION IP in the allowlist (egress_map)
// - Attached to TC INGRESS on host-side veth (sees packets FROM pod)
// - Uses egress_map and egress_pod_state_map

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define BPF_F_NO_PREALLOC 1
#define ETH_HLEN 14
#define BPF_MAP_ID_INGRESS_MAP 2
#define MAX_RULES 256
#define MIN_RULES 128
#define PIN_GLOBAL_NS 2
#define RESERVED_IP_PROTOCOL 255
#define ANY_IP_PROTOCOL 254
#define ANY_PORT 0
#define MAX_PORT_PROTOCOL 24
#define POLICIES_APPLIED 0
#define DEFAULT_ALLOW 1
#define DEFAULT_DENY 2
#define ERROR_TIER 0
#define ADMIN_TIER 1
#define NETWORK_POLICY_TIER 2
#define BASELINE_TIER 3
#define DEFAULT_TIER 4
#define ACTION_DENY 0
#define ACTION_ALLOW 1
#define ACTION_PASS 2
#define MAX_RULE_PRIORITY 65536
#define ADMIN_TIER_PRIORITY_LIMIT 1000
#define NETWORK_POLICY_TIER_PRIORITY 1500
#define CT_VAL_DEFAULT_ALLOW 0
#define CT_VAL_DEFAULT_ALLOW_DEFAULT_ALLOW 2
#define CT_VAL_DEFAULT_ALLOW_DEFAULT_DENY 3
#define CT_VAL_DEFAULT_ALLOW_POLICIES_APPLIED 4
#define CT_VAL_POLICIES_APPLIED_DEFAULT_ALLOW 5
#define CT_VAL_POLICIES_APPLIED_DEFAULT_DENY 6
#define CT_VAL_POLICIES_APPLIED_POLICIES_APPLIED 7

#define GET_CT_VAL(a, b) \
    ((a) == DEFAULT_ALLOW && (b) == DEFAULT_ALLOW ? CT_VAL_DEFAULT_ALLOW_DEFAULT_ALLOW : \
     (a) == DEFAULT_ALLOW && (b) == DEFAULT_DENY  ? CT_VAL_DEFAULT_ALLOW_DEFAULT_DENY  : \
     (a) == DEFAULT_ALLOW && (b) == POLICIES_APPLIED ? CT_VAL_DEFAULT_ALLOW_POLICIES_APPLIED : \
     (a) == POLICIES_APPLIED && (b) == DEFAULT_ALLOW ? CT_VAL_POLICIES_APPLIED_DEFAULT_ALLOW : \
     (a) == POLICIES_APPLIED && (b) == DEFAULT_DENY  ? CT_VAL_POLICIES_APPLIED_DEFAULT_DENY  : \
	 (a) == POLICIES_APPLIED && (b) == POLICIES_APPLIED ? CT_VAL_POLICIES_APPLIED_POLICIES_APPLIED : \
     CT_VAL_POLICIES_APPLIED_POLICIES_APPLIED)

struct keystruct
{
  __u32 prefix_len;
  __u8  ip[4];
};

struct lpm_trie_key {
    __u32 prefixlen;
    __u32 ip;
};

struct lpm_trie_val {
    __u32 protocol;
    __u32 start_port;
    __u32 end_port;
};

struct lpm_cp_trie_val {
    __u32 protocol;
	__u32 priority;
    __u32 start_port;
    __u32 end_port;
};

struct conntrack_key {
   __u32 src_ip;
   __u16 src_port;
   __u32 dest_ip;
   __u16 dest_port;
   __u8  protocol;
   __u32 owner_ip;
};

struct conntrack_value {
   __u8 val; // 0 => default-allow, 1 => policies-applied
};

struct data_t {
	__u32  src_ip;
	__u32  src_port;
	__u32  dest_ip;
	__u32  dest_port;
	__u32  protocol;
	__u32  verdict;
	__u32 packet_sz;
	__u8 is_egress;
	__u8 tier;
};

struct pod_state {
    __u8 state; // 0 => POLICIES_APPLIED, 1 => DEFAULT_ALLOW, 2 => DEFAULT_DENY
};

// Modern BTF-based map definitions (libbpf 1.0+)
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(key_size, sizeof(struct lpm_trie_key));
	__uint(value_size, sizeof(struct lpm_cp_trie_val[MAX_PORT_PROTOCOL]));
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} cp_egress_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(key_size, sizeof(struct lpm_trie_key));
	__uint(value_size, sizeof(struct lpm_trie_val[MAX_PORT_PROTOCOL]));
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} egress_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct pod_state));
	__uint(max_entries, 2);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} egress_pod_state_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct conntrack_key));
	__uint(value_size, sizeof(struct conntrack_value));
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} aws_conntrack_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);  // 256KB ring buffer
} policy_events SEC(".maps");

static __always_inline int evaluateClusterPolicyByLookUp(struct keystruct trie_key, struct conntrack_key flow_key, __u32 *admin_tier_priority, __u8 *baseline_tier_action, __u32 *baseline_tier_priority) {

	__u32 admin_tier_action = ACTION_PASS;
	*baseline_tier_action = ACTION_PASS;
	*admin_tier_priority = MAX_RULE_PRIORITY;
	*baseline_tier_priority = MAX_RULE_PRIORITY;

	struct lpm_cp_trie_val *trie_val = bpf_map_lookup_elem(&cp_egress_map, &trie_key);

	if (trie_val == NULL) {
		// No cluster policy rules exist, so we pass by default
		return ACTION_PASS;
	}

	for (int i = 0; i < MAX_PORT_PROTOCOL; i++, trie_val++){

		__u32 priority = trie_val->priority/10;
		__u32 action = trie_val->priority%10;

		if ((trie_val->protocol == ANY_IP_PROTOCOL) || (trie_val->protocol == flow_key.protocol &&
					((trie_val->start_port == ANY_PORT) || (flow_key.dest_port == trie_val->start_port) ||
						(trie_val->end_port > 0 && flow_key.dest_port >= trie_val->start_port && flow_key.dest_port <= trie_val->end_port)))) {
			// Update admin tier
			if (priority < *admin_tier_priority ||
			   (priority == *admin_tier_priority && action < admin_tier_action)) {
				*admin_tier_priority = priority;
				admin_tier_action = action;
			}

			// Update baseline tier
			if (priority > ADMIN_TIER_PRIORITY_LIMIT &&
				(priority < *baseline_tier_priority ||
				(priority == *baseline_tier_priority && action < *baseline_tier_action))) {
				*baseline_tier_priority = priority;
				*baseline_tier_action = action;
			}
		}
	}

	return admin_tier_action;
}

static __always_inline int evaluateNamespacePolicyByLookUp(struct keystruct trie_key, struct conntrack_key flow_key, int pod_state) {
	//Check if it's in the allowed list
	struct lpm_trie_val *trie_val = bpf_map_lookup_elem(&egress_map, &trie_key);

	if (trie_val == NULL) {
		if (pod_state != POLICIES_APPLIED) {
			// No namespace policy rules exist, so we pass to baseline rules. The pod is in default-allow or default-deny state
			return ACTION_PASS;
		}
		return ACTION_DENY;
	}

	for (int i = 0; i < MAX_PORT_PROTOCOL; i++, trie_val++){
		if (trie_val->protocol == RESERVED_IP_PROTOCOL) {
			return ACTION_DENY;
		}
		
		if ((trie_val->protocol == ANY_IP_PROTOCOL && 
			((trie_val->start_port == ANY_PORT) || (flow_key.dest_port == trie_val->start_port) ||
			(flow_key.dest_port > trie_val->start_port && flow_key.dest_port <= trie_val->end_port))) ||
			(trie_val->protocol == flow_key.protocol &&
			((trie_val->start_port == ANY_PORT) || (flow_key.dest_port == trie_val->start_port) ||
			(flow_key.dest_port > trie_val->start_port && flow_key.dest_port <= trie_val->end_port)))) {
			return ACTION_ALLOW;
		}
	}
	return ACTION_DENY;
}

static __always_inline int evaluateFlow(struct keystruct trie_key, struct conntrack_key flow_key, __u8 pod_state_val, struct data_t *evt, int pod_state) {

		struct conntrack_value flow_val = {};

		__u32 admin_tier_priority;
		__u8 baseline_tier_action;
		__u32 baseline_tier_priority;
		int effective_action;

		// DEBUG: Print flow evaluation (IP in hex, ports, protocol)
		bpf_trace_printk("[EGRESS] Flow: src_ip=0x%x sport=%d\n", sizeof("[EGRESS] Flow: src_ip=0x%x sport=%d\n"), flow_key.src_ip, flow_key.src_port);
		bpf_trace_printk("[EGRESS]       dst_ip=0x%x dport=%d proto=%d\n", sizeof("[EGRESS]       dst_ip=0x%x dport=%d proto=%d\n"), flow_key.dest_ip, flow_key.dest_port, flow_key.protocol);

		int admin_tier_action = evaluateClusterPolicyByLookUp(trie_key, flow_key, &admin_tier_priority, &baseline_tier_action, &baseline_tier_priority);
		if (admin_tier_priority <= ADMIN_TIER_PRIORITY_LIMIT) {
			// Enforce the lowest priority action. Deny always takes precedence on same priority
			effective_action = admin_tier_action;
			switch (effective_action) {
			case ACTION_DENY: {
				bpf_trace_printk("[EGRESS] ADMIN_TIER: DENY", sizeof("[EGRESS] ADMIN_TIER: DENY"));
				evt->verdict = 0;
				evt->tier = ADMIN_TIER;
				// bpf_ringbuf_output(&policy_events, evt, sizeof(*evt), 0);
				return BPF_DROP;
			}
			case ACTION_ALLOW: {
				bpf_trace_printk("[EGRESS] ADMIN_TIER: ALLOW", sizeof("[EGRESS] ADMIN_TIER: ALLOW"));
				flow_val.val = pod_state_val;
				bpf_map_update_elem(&aws_conntrack_map, &flow_key, &flow_val, 0);
				evt->verdict = 1;
				evt->tier = ADMIN_TIER;
				// bpf_ringbuf_output(&policy_events, evt, sizeof(*evt), 0);
				return BPF_OK;
			}
			default:
				break; // ACTION_PASS
			}
		}

		int verdict = evaluateNamespacePolicyByLookUp(trie_key, flow_key, pod_state);

		switch (verdict){
		case ACTION_ALLOW:{
			bpf_trace_printk("[EGRESS] NETWORK_POLICY_TIER: ALLOW", sizeof("[EGRESS] NETWORK_POLICY_TIER: ALLOW"));
			flow_val.val = pod_state_val;
			bpf_map_update_elem(&aws_conntrack_map, &flow_key, &flow_val, 0); // 0 - BPF_ANY
			evt->verdict = 1;
			evt->tier = NETWORK_POLICY_TIER;
			// bpf_ringbuf_output(&policy_events, evt, sizeof(*evt), 0);
			return BPF_OK;
		}
		case ACTION_DENY:{
			bpf_trace_printk("[EGRESS] NETWORK_POLICY_TIER: DENY", sizeof("[EGRESS] NETWORK_POLICY_TIER: DENY"));
			evt->verdict = 0;
			evt->tier = NETWORK_POLICY_TIER;
			// bpf_ringbuf_output(&policy_events, evt, sizeof(*evt), 0);
			return BPF_DROP;
		}
		case ACTION_PASS:
			effective_action = baseline_tier_action;
			switch (effective_action) {
			case ACTION_DENY: {
				bpf_trace_printk("[EGRESS] BASELINE_TIER: DENY", sizeof("[EGRESS] BASELINE_TIER: DENY"));
				evt->verdict = 0;
				evt->tier = BASELINE_TIER;
				// bpf_ringbuf_output(&policy_events, evt, sizeof(*evt), 0);
				return BPF_DROP;
			}
			case ACTION_ALLOW: {
				bpf_trace_printk("[EGRESS] BASELINE_TIER: ALLOW", sizeof("[EGRESS] BASELINE_TIER: ALLOW"));
				flow_val.val = pod_state_val;
				bpf_map_update_elem(&aws_conntrack_map, &flow_key, &flow_val, 0);
				evt->verdict = 1;
				evt->tier = BASELINE_TIER;
				// bpf_ringbuf_output(&policy_events, evt, sizeof(*evt), 0);
				return BPF_OK;
			}
			case ACTION_PASS: {
				switch (pod_state) {
				case DEFAULT_ALLOW: {
					bpf_trace_printk("[EGRESS] DEFAULT_TIER: ALLOW", sizeof("[EGRESS] DEFAULT_TIER: ALLOW"));
					flow_val.val = pod_state_val;
					bpf_map_update_elem(&aws_conntrack_map, &flow_key, &flow_val, 0);
					evt->verdict = 1;
					evt->tier = DEFAULT_TIER;
					// bpf_ringbuf_output(&policy_events, evt, sizeof(*evt), 0);
					return BPF_OK;
					}
				case DEFAULT_DENY: {
					bpf_trace_printk("[EGRESS] DEFAULT_TIER: DENY", sizeof("[EGRESS] DEFAULT_TIER: DENY"));
					evt->verdict = 0;
					evt->tier = DEFAULT_TIER;
					// bpf_ringbuf_output(&policy_events, evt, sizeof(*evt), 0);
					return BPF_DROP;
					}
				}
			}
		}
	}
	return BPF_DROP;
}


SEC("tc_cls")
int handle_egress(struct __sk_buff *skb)
{
	struct keystruct trie_key;
	__u32 l4_src_port = 0;
	__u32 l4_dst_port = 0;
	struct conntrack_key flow_key;
	struct conntrack_value *flow_val;
	struct conntrack_key reverse_flow_key;
	struct conntrack_value *reverse_flow_val;
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	__u8 src_ip[4];

	__builtin_memset(&flow_key, 0, sizeof(flow_key));
	__builtin_memset(&src_ip, 0, sizeof(src_ip));
	__builtin_memset(&reverse_flow_key, 0, sizeof(reverse_flow_key));


	struct ethhdr *ether = data;
	if (data + sizeof(*ether) > data_end) {
		return BPF_OK;
	}

	// Check for IPv4: ethertype 0x0800 
	// h_proto is __be16 (network byte order), compare directly with 0x0800
	__u16 h_proto = ether->h_proto;
	if ((h_proto & 0xFF) == 0x08 && (h_proto >> 8) == 0x00) {  // IPv4: 0x08 0x00 in network order
		data += sizeof(*ether);
		struct iphdr *ip = data;
		struct tcphdr *l4_tcp_hdr = data + sizeof(struct iphdr);
		struct udphdr *l4_udp_hdr = data + sizeof(struct iphdr);
		struct sctphdr *l4_sctp_hdr = data + sizeof(struct iphdr);

		if (data + sizeof(*ip) > data_end) {
			return BPF_OK;
		}
		if (ip->version != 4) {
			return BPF_OK;
		}

		switch (ip->protocol) {
			case IPPROTO_TCP:
				if (data + sizeof(*ip) + sizeof(*l4_tcp_hdr) > data_end) {
					return BPF_OK;
				}
				l4_src_port = (((((unsigned short)(l4_tcp_hdr->source) & 0xFF)) << 8) | (((unsigned short)(l4_tcp_hdr->source) & 0xFF00) >> 8));
				l4_dst_port = (((((unsigned short)(l4_tcp_hdr->dest) & 0xFF)) << 8) | (((unsigned short)(l4_tcp_hdr->dest) & 0xFF00) >> 8));
				break;
			case IPPROTO_UDP:
				if (data + sizeof(*ip) + sizeof(*l4_udp_hdr) > data_end) {
					return BPF_OK;
				}
				l4_src_port = (((((unsigned short)(l4_udp_hdr->source) & 0xFF)) << 8) | (((unsigned short)(l4_udp_hdr->source) & 0xFF00) >> 8));
				l4_dst_port = (((((unsigned short)(l4_udp_hdr->dest) & 0xFF)) << 8) | (((unsigned short)(l4_udp_hdr->dest) & 0xFF00) >> 8));
				break;
			case IPPROTO_SCTP:
				if (data + sizeof(*ip) + sizeof(*l4_sctp_hdr) > data_end) {
					return BPF_OK;
				}
				l4_src_port = (((((unsigned short)(l4_sctp_hdr->source) & 0xFF)) << 8) | (((unsigned short)(l4_sctp_hdr->source) & 0xFF00) >> 8));
				l4_dst_port = (((((unsigned short)(l4_sctp_hdr->dest) & 0xFF)) << 8) | (((unsigned short)(l4_sctp_hdr->dest) & 0xFF00) >> 8));
				break;
		}

		// KEY DIFFERENCE: For EGRESS, check DESTINATION IP in allowlist
		trie_key.prefix_len = 32;
		trie_key.ip[0] = ip->daddr & 0xff;
		trie_key.ip[1] = (ip->daddr >> 8) & 0xff;
		trie_key.ip[2] = (ip->daddr >> 16) & 0xff;
		trie_key.ip[3] = (ip->daddr >> 24) & 0xff;

		src_ip[0] = ip->saddr & 0xff;
		src_ip[1] = (ip->saddr >> 8) & 0xff;
		src_ip[2] = (ip->saddr >> 16) & 0xff;
		src_ip[3] = (ip->saddr >> 24) & 0xff;

		// Check for an existing flow in the conntrack table
		flow_key.src_ip = ip->saddr;
		flow_key.src_port = l4_src_port;
		flow_key.dest_ip = ip->daddr;
		flow_key.dest_port = l4_dst_port;
		flow_key.protocol = ip->protocol;
		flow_key.owner_ip = ip->saddr;  // Owner is the pod (source)

		struct data_t evt = {};
		evt.src_ip = flow_key.src_ip;
		evt.src_port = flow_key.src_port;
		evt.dest_ip = flow_key.dest_ip;
		evt.dest_port = flow_key.dest_port;
		evt.protocol = flow_key.protocol;
		evt.is_egress = 1;
		evt.packet_sz = skb->len;

		__u32 NETWORK_POLICY_KEY = 0; 
		__u32 CLUSTER_NETWORK_POLICY_KEY = 1;

		struct pod_state *clusterpolicy_pst = bpf_map_lookup_elem(&egress_pod_state_map, &CLUSTER_NETWORK_POLICY_KEY);
		struct pod_state *pst = bpf_map_lookup_elem(&egress_pod_state_map, &NETWORK_POLICY_KEY);

		// There should always be an entry in pod_state_map. pst returned in above line should never be null.
		if ((pst == NULL) || (clusterpolicy_pst == NULL)) {
			bpf_trace_printk("[EGRESS] ERROR: pod_state_map not initialized", sizeof("[EGRESS] ERROR: pod_state_map not initialized"));
			evt.verdict = 0;
			evt.tier = ERROR_TIER;
			// bpf_ringbuf_output(&policy_events, &evt, sizeof(evt), 0);
			return BPF_DROP;
		}

		__u8 ct_pod_state_val = GET_CT_VAL(pst->state, clusterpolicy_pst->state);

		bpf_trace_printk("[EGRESS] Packet: src=0x%x dst=0x%x proto=%d\n", sizeof("[EGRESS] Packet: src=0x%x dst=0x%x proto=%d\n"), flow_key.src_ip, flow_key.dest_ip, flow_key.protocol);

		// Check if it's an existing flow
		flow_val = bpf_map_lookup_elem(&aws_conntrack_map, &flow_key);

		if (flow_val != NULL) {
			// If the pod state matches, allow the packet
			if (flow_val->val == ct_pod_state_val) {
				bpf_trace_printk("[EGRESS] Existing flow matched", sizeof("[EGRESS] Existing flow matched"));
				return BPF_OK;
			}

			// Evaluate the flow again if the pod state has changed and take the decision based on it
			if (flow_val->val != ct_pod_state_val) {
				bpf_trace_printk("[EGRESS] Pod state changed, re-evaluating", sizeof("[EGRESS] Pod state changed, re-evaluating"));
				int ret = evaluateFlow(trie_key, flow_key, ct_pod_state_val, &evt, pst->state);
				if (ret == BPF_DROP) {
					bpf_map_delete_elem(&aws_conntrack_map, &flow_key);
					return BPF_DROP;
				}
				return BPF_OK;
			}
		}

		//Check for the reverse flow entry in the conntrack table
		reverse_flow_key.src_ip = ip->daddr;
		reverse_flow_key.src_port = l4_dst_port;
		reverse_flow_key.dest_ip = ip->saddr;
		reverse_flow_key.dest_port = l4_src_port;
		reverse_flow_key.protocol = ip->protocol;
		reverse_flow_key.owner_ip = ip->saddr;

		//Check if it's a response packet
		reverse_flow_val = bpf_map_lookup_elem(&aws_conntrack_map, &reverse_flow_key);

		if (reverse_flow_val != NULL) {
			bpf_trace_printk("[EGRESS] Reverse flow matched (response)", sizeof("[EGRESS] Reverse flow matched (response)"));
			return BPF_OK;
		}

		bpf_trace_printk("[EGRESS] New flow - evaluating policy\n", sizeof("[EGRESS] New flow - evaluating policy\n"));
		// If we reach here, it means it's a new flow or a non-matching response
		return evaluateFlow(trie_key, flow_key, ct_pod_state_val, &evt, pst->state);
	}
	return BPF_OK;
}

char _license[] SEC("license") = "GPL";
