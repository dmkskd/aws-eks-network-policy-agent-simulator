# AWS VPC CNI Network Policy Simulator

## Overview

This project demonstrates AWS VPC CNI's network policy enforcement using eBPF. It simulates a realistic multi-pod Kubernetes scenario with ingress traffic control.

## Architecture

### Network Topology

```
┌─────────────────────────────────────────────────────────┐
│  Host (br-sim bridge: 10.0.0.1/24)                      │
│                                                         │
│  ┌────────────────────┐  ┌─────────────────────────┐    │
│  │  Backend Pod       │  │  Allowed Client Pod     │    │
│  │  10.0.0.10:8080    │  │  10.0.0.20              │    │
│  │  (protected)       │  │  (can connect)          │    │
│  │  eBPF attached ──► │  └─────────────────────────┘    │
│  └────────────────────┘                                 │
│                                                         │
│  ┌─────────────────────────┐                            │
│  │  Denied Client Pod      │                            │
│  │  10.0.0.30              │                            │
│  │  (blocked by policy)    │                            │
│  └─────────────────────────┘                            │
└─────────────────────────────────────────────────────────┘
```

## Pods

- **Backend**: Service pod listening on TCP port 8080 (IP: 10.0.0.10)
- **Allowed Client**: Can access backend (IP: 10.0.0.20)
- **Denied Client**: Blocked by network policy (IP: 10.0.0.30)

## eBPF Program

### Source

The BPF program is derived from [AWS VPC CNI Network Policy Agent](https://github.com/aws/aws-network-policy-agent):
- **File**: `tc.v4ingress.bpf.c`
- **License**: Apache 2.0
- **Section**: `tc_cls`
- **Hook**: TC (Traffic Control) ingress on backend's veth interface

### Policy Enforcement Tiers

The AWS implementation uses a 5-tier policy system:

1. **ERROR_TIER**: Pod state map not initialized (deny)
2. **ADMIN_TIER**: Cluster-wide admin policies (highest priority)
3. **NETWORK_POLICY_TIER**: Namespace-scoped policies
4. **BASELINE_TIER**: Baseline cluster policies
5. **DEFAULT_TIER**: Default pod policy (allow/deny)

### Key BPF Maps

- `ingress_map`: LPM trie for namespace policies (IP → protocol/port rules)
- `cp_ingress_map`: LPM trie for cluster policies
- `ingress_pod_state_map`: Pod policy state (POLICIES_APPLIED, DEFAULT_ALLOW, DEFAULT_DENY)
- `aws_conntrack_map`: Connection tracking for stateful filtering


## Quick Start

### Prerequisites

```bash
# Must run as root
sudo su

# Required packages
apt install -y clang llvm libbpf-dev iproute2 bpftool netcat
```

### Launch TUI

Must run as root

```bash
./run.sh
```


## How It Works

### 1. Packet Flow

```
Client Pod → veth-pod → veth-host-bridge → Bridge → Backend veth-host
                                                              ↓
                                                         eBPF TC ingress
                                                              ↓
                                                    Policy Evaluation
                                                     (5-tier system)
                                                              ↓
                                               [ALLOW] → Backend Pod
                                               [DENY]  → Drop packet
```

### 2. Policy Evaluation

For each incoming packet:
1. **Parse**: Extract IP header, L4 protocol, ports
2. **Conntrack Lookup**: Check if existing connection
3. **Pod State Check**: Get pod's default policy state
4. **Tier Evaluation**:
   - Cluster admin policies (highest priority)
   - Namespace network policies
   - Baseline policies
   - Default allow/deny
5. **Verdict**: Allow (BPF_OK) or Drop (BPF_DROP)

### 3. Connection Tracking

- Tracks established connections in `aws_conntrack_map`
- Bidirectional flow awareness
- Adapts when pod policy state changes


## License

- AWS VPC CNI source: Apache 2.0
- Modifications: Same (Apache 2.0)

## References

- [AWS Network Policy Agent](https://github.com/aws/aws-network-policy-agent)
- [eBPF TC Documentation](https://docs.kernel.org/bpf/prog_cgroup_sockopt.html)
- [BPF Type Format (BTF)](https://www.kernel.org/doc/html/latest/bpf/btf.html)
