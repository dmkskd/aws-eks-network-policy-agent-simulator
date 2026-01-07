# AWS VPC CNI Network Policy Implementation

## High-Level Architecture

The AWS network policy implementation uses **eBPF** rather than iptables, which is a significant architectural choice. Here's how the components fit together:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Control Plane                                │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │     amazon-network-policy-controller-k8s                 │   │
│  │     (Deployment in kube-system)                          │   │
│  │                                                          │   │
│  │  Watches: NetworkPolicy (networking.k8s.io),             │   │
│  │           AdminNetworkPolicy (policy.networking.k8s.io), │   │
│  │           BaselineAdminNetworkPolicy                     │   │
│  │                                                          │   │
│  │  Produces: PolicyEndpoints (networking.k8s.aws)          │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ PolicyEndpoints (networking.k8s.aws)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Data Plane (per node)                        │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │     aws-network-policy-agent (DaemonSet)                 │   │
│  │                                                          │   │
│  │  - Watches PolicyEndpoints (networking.k8s.aws)          │   │
│  │  - Resolves pod IPs                                      │   │
│  │  - Programs eBPF maps                                    │   │
│  └──────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              │ BPF syscalls                     │
│                              ▼                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │     eBPF Programs (attached to pod veth interfaces)      │   │
│  │                                                          │   │
│  │  - Ingress: tc classifier on host-side veth              │   │
│  │  - Egress: tc classifier on host-side veth               │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Network Topology Detail

In a typical setup with multiple pods:

```
┌────────────────────────────────────────┐
│         Host Network Namespace         │
│  ┌──────────────────────────────────┐  │
│  │   Bridge (br-sim) - 10.0.0.1/24  │  │
│  └──────────────────────────────────┘  │
│              │                         │
│    ┌─────────┼───────────┐             │
│    │         │           │             │
│ veth-be-h  veth-allow veth-deny        │ ← Host-side veth interfaces (eBPF attached here)
│    │         │           │             │
└────┼─────────┼───────────┼─────────────┘
     │         │           │
     │         │           │ veth pairs
     │         │           │
┌────┼─────┐ ┌─┼────────┐ ┌┼──────────┐
│ veth-be-p│ │veth-allow│ │veth-deny-p│  ← Pod-side veth interfaces
│          │ │   -p     │ │           │
│ Backend  │ │ Allowed  │ │  Denied   │
│   Pod    │ │  Client  │ │  Client   │
│10.0.0.10 │ │10.0.0.20 │ │10.0.0.30  │
└──────────┘ └──────────┘ └───────────┘
```

### eBPF Program Attachment (for Backend Pod)

```
Host veth: veth-be-h
     │
     ├── TC EGRESS hook ──────> tc.v4ingress.bpf.o (K8s Ingress policy)
     │                          - Sees packets TO pod (10.0.0.10)
     │                          - Checks SOURCE IP in ingress_map
     │                          - Filters: "Who can connect TO this pod?"
     │
     └── TC INGRESS hook ─────> tc.v4egress.bpf.o (K8s Egress policy)
                                - Sees packets FROM pod (10.0.0.10)
                                - Checks DESTINATION IP in egress_map
                                - Filters: "Where can this pod connect TO?"
```

---

## Component Deep Dive

### 1. Network Policy Controller (`amazon-network-policy-controller-k8s`)

**Repository**: https://github.com/aws/amazon-network-policy-controller-k8s

This is a standard controller-runtime based controller that:

- Watches `NetworkPolicy` (`networking.k8s.io/v1` - standard k8s), plus the newer `AdminNetworkPolicy` and `BaselineAdminNetworkPolicy` (`policy.networking.k8s.io` - from k8s-sigs)
- Resolves label selectors to actual pod endpoints
- Produces a `PolicyEndpoints` (`networking.k8s.aws/v1alpha1`) custom resource that's essentially a "compiled" version of the policy with resolved IPs

**The key insight**: The separation of concerns - the controller handles the complex label selection and policy resolution, while the node agent just deals with IPs and ports.

### 2. Network Policy Agent (`aws-network-policy-agent`)

**Repository**: https://github.com/aws/aws-network-policy-agent

Runs as a **DaemonSet** (typically as a container within the `aws-node` pod alongside the VPC CNI). Its responsibilities:

1. Watch `PolicyEndpoints` (`networking.k8s.aws/v1alpha1`) for policies affecting pods on this node
2. Maintain eBPF maps with the allow/deny rules
3. Attach eBPF programs to pod network interfaces

The agent uses the **BPF filesystem** (`/sys/fs/bpf`) to pin maps and programs, allowing them to persist across agent restarts.

### 3. eBPF Programs

The eBPF programs are attached as **TC (Traffic Control) classifiers** on the host-side of the pod's veth pair.

```
Pod namespace          │  Host namespace
                       │
   eth0 ←──────────────┼─── veth (eBPF attached here)
                       │         │
                       │         ├── tc ingress: policy for traffic TO pod
                       │         └── tc egress: policy for traffic FROM pod
```

The programs consult eBPF maps that contain:

- **Trie maps** for CIDR matching (LPM trie)
- **Hash maps** for exact IP:port matching
- **Array maps** for policy metadata

---

## Packet Flow (Ingress to Pod)

```
1. Packet arrives at node ENI
2. VPC CNI routing sends it toward pod's veth
3. TC ingress hook on veth fires
4. eBPF program executes:
   a. Extract src IP, dst port, protocol
   b. Look up destination pod in map
   c. Find applicable policies
   d. Check if (src IP, dst port, protocol) matches any allow rule
   e. Return TC_ACT_OK (allow) or TC_ACT_SHOT (drop)
5. If allowed, packet enters pod namespace
```

---

## Key Implementation Details

### Critical Understanding: eBPF Program Naming vs TC Attachment

**The program names use Kubernetes terminology, NOT TC terminology:**

| K8s Policy Type | eBPF Program | TC Attachment Point | What It Filters |
|----------------|--------------|---------------------|-----------------|
| **Ingress** (TO pod) | `tc.v4ingress.bpf.c` | TC **EGRESS** on host veth | Checks **SOURCE IP** |
| **Egress** (FROM pod) | `tc.v4egress.bpf.c` | TC **INGRESS** on host veth | Checks **DESTINATION IP** |

TC egress/ingress is from the **interface's perspective** (host veth), while K8s Ingress/Egress is from the **pod's perspective**.

**TC clsact qdisc:**  
- "classless action" - a lightweight qdisc designed specifically for BPF attachment
- Provides two hooks: ingress (packets entering interface) and egress (packets leaving interface)
- No actual queuing/classification overhead - pure attachment point
- `direct-action` flag means eBPF program returns verdict directly (`TC_ACT_OK` or `TC_ACT_SHOT`)

### Why eBPF over iptables?

1. **Performance**: O(1) map lookups vs O(n) iptables rule traversal
2. **Scalability**: No iptables lock contention with many policies
3. **Atomicity**: Map updates are atomic; no "policy gap" during updates
4. **Visibility**: eBPF maps can be inspected, and programs can emit events for debugging

### The PolicyEndpoints CRD (`networking.k8s.aws/v1alpha1`)

This is the "compiled" policy format specific to AWS. Looking at the structure:

```yaml
apiVersion: networking.k8s.aws/v1alpha1
kind: PolicyEndpoints
metadata:
  name: <policy-name>-<hash>
  namespace: <namespace>
spec:
  podSelectorEndpoints:
    - hostIP: 10.0.1.5
      podIP: 10.0.1.50
      name: my-pod
      namespace: default
  ingress:
    - cidr: 10.0.0.0/16
      except:
        - 10.0.2.0/24
      ports:
        - port: 80
          protocol: TCP
  egress:
    # similar structure
```

- Standard `NetworkPolicy` (`networking.k8s.io/v1`) uses pod selectors (labels like `app=frontend`)
- `PolicyEndpoints` (`networking.k8s.aws/v1alpha1`) contains resolved concrete IPs
- One NetworkPolicy → multiple PolicyEndpoints (one per target pod)
- Easier for the agent to consume: no label resolution needed

### Conntrack Integration: Bidirectional Flow

Both ingress and egress programs use `aws_conntrack_map` to cache policy decisions, enabling **bidirectional communication**:

#### First Packet (SYN)
```
Client → Backend: SYN packet
  ├─> Hits INGRESS program (TC egress on veth-be-h)
  ├─> Evaluates: Is 10.0.0.20 in ingress_map?
  ├─> ✅ ALLOW
  └─> Stores in conntrack: key={src:10.0.0.20, dst:10.0.0.10, ...}
```

#### Response Packet (SYN-ACK)
```
Backend → Client: SYN-ACK packet
  ├─> Hits EGRESS program (TC ingress on veth-be-h)
  ├─> Checks REVERSE flow in conntrack
  ├─> Finds: {src:10.0.0.20, dst:10.0.0.10, ...} exists
  └─> ✅ ALLOW (reverse flow matched)
```

**Key Code** (in both programs):
```c
reverse_flow_key.src_ip = ip->daddr;      // Reverse: dest becomes source  
reverse_flow_key.dest_ip = ip->saddr;     // Reverse: source becomes dest
reverse_flow_val = bpf_map_lookup_elem(&aws_conntrack_map, &reverse_flow_key);
if (reverse_flow_val != NULL) {
    bpf_trace_printk("Reverse flow matched (response)", ...);
    return BPF_OK;  // Allow the response!
}
```

This enables **bidirectional communication** with policy checks only on the first packet of each flow.

---

## Control Plane → Data Plane Flow

### Step 1: User Creates NetworkPolicy (`networking.k8s.io/v1`)

```bash
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-policy
spec:
  podSelector:
    matchLabels:
      app: backend
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
EOF
```

### Step 2: Controller Processes

**Network Policy Controller**:
1. Watches NetworkPolicy (`networking.k8s.io/v1`) via Kubernetes API
2. Resolves `app=backend` → pod IPs: `[10.0.1.5, 10.0.1.6]`
3. Resolves `app=frontend` → pod IPs: `[10.0.2.10, 10.0.2.11]`
4. Creates `PolicyEndpoints` (`networking.k8s.aws/v1alpha1`) CRD:

```yaml
apiVersion: networking.k8s.aws/v1alpha1
kind: PolicyEndpoints
metadata:
  name: backend-policy-10-0-1-5
spec:
  podSelectorEndpoints:
    - podIP: 10.0.1.5
      name: backend-pod-1
  ingress:
    - cidr: 10.0.2.10/32
      ports:
        - port: 8080
          protocol: TCP
    - cidr: 10.0.2.11/32
      ports:
        - port: 8080
          protocol: TCP
```

### Step 3: Agent Programs eBPF

**Network Policy Agent** (on node hosting pod 10.0.1.5):

1. Watches `PolicyEndpoints` (`networking.k8s.aws/v1alpha1`) CRD
2. Identifies local pod: `10.0.1.5`
3. Finds pod's host-side veth interface: `eni3a7f8b2c`
4. Attaches eBPF programs:

```bash
# Create clsact qdisc (if not exists)
tc qdisc add dev eni3a7f8b2c clsact

# Attach ingress eBPF program (for traffic TO pod) on TC EGRESS
tc filter add dev eni3a7f8b2c egress \
   bpf direct-action \
   obj ingress_policy.o \
   sec classifier/tc_cls

# Attach egress eBPF program (for traffic FROM pod) on TC INGRESS
tc filter add dev eni3a7f8b2c ingress \
   bpf direct-action \
   obj egress_policy.o \
   sec classifier/tc_cls
```

5. Updates eBPF maps:

```c
// ingress_map (LPM trie) - stores allowed SOURCE IPs
Key: { prefix_len: 32, ip: [10, 0, 2, 10] }  // 10.0.2.10
Value: { protocol: TCP, port: 8080 }
Action: ALLOW

Key: { prefix_len: 32, ip: [10, 0, 2, 11] }  // 10.0.2.11
Value: { protocol: TCP, port: 8080 }
Action: ALLOW

// ingress_pod_state_map - stores pod policy mode
Key: { pod_ip: 10.0.1.5 }
Value: POLICIES_APPLIED (0)  // Deny-by-default
```

### Step 4: Packet Processing

**When packet arrives** from frontend (10.0.2.10 → 10.0.1.5:8080):

```
1. Packet arrives at node ENI
2. VPC CNI routes to pod's veth: eni3a7f8b2c
3. TC ingress hook fires on eni3a7f8b2c
4. eBPF program executes in kernel:
   
   parse_packet() {
     src_ip = 10.0.2.10
     dst_ip = 10.0.1.5
     dst_port = 8080
     protocol = TCP
   }
   
   build_trie_key(src_ip) {
     trie_key = { prefix_len: 32, ip: [10, 0, 2, 10] }
   }
   
   lookup_ingress_map(trie_key) {
     // FOUND! 10.0.2.10 is allowed
     return ALLOW, port=8080
   }
   
   check_port(8080 == 8080) → MATCH
   
   update_conntrack() {
     conntrack_key = {src: 10.0.2.10, dst: 10.0.1.5, dport: 8080, proto: TCP}
     conntrack_value = {state: ESTABLISHED, timestamp: now()}
   }
   
   return TC_ACT_OK  // Allow packet
   
5. Packet enters pod namespace via veth pair
6. Application in pod receives packet on port 8080
```

**When packet arrives** from unauthorized source (10.0.3.50 → 10.0.1.5:8080):

```
4. eBPF program executes:
   
   build_trie_key(src_ip) {
     trie_key = { prefix_len: 32, ip: [10, 0, 3, 50] }
   }
   
   lookup_ingress_map(trie_key) {
     // NOT FOUND - no matching rule
   }
   
   check_pod_state(10.0.1.5) {
     // pod_state = POLICIES_APPLIED (deny-by-default)
   }
   
   return TC_ACT_SHOT  // Drop packet
   
5. Packet dropped in kernel, never reaches pod
```

### Program Logic Deep Dive

#### Ingress Program (tc.v4ingress.bpf.c)

**Attachment**: TC egress on host-side veth (e.g., `veth-be-h`)

**Packet Flow**:
```
Client (10.0.0.20) ──> veth-allow-h ──> bridge ──> veth-be-h ──[TC EGRESS]──> veth-be-p ──> Backend Pod
                                                                     │
                                                                     └─> INGRESS PROGRAM
                                                                         sees: src=10.0.0.20
                                                                               dst=10.0.0.10
```

**Logic** (simplified from actual code):
```c
// Build trie key from SOURCE IP
trie_key.prefix_len = 32;
trie_key.ip[0] = ip->saddr & 0xff;  // SOURCE IP (10.0.0.20)
// ... [remaining IP bytes]

// Set protected pod IP
flow_key.owner_ip = ip->daddr;  // Protected pod (10.0.0.10)

// Check if SOURCE IP (10.0.0.20) is in ingress_map
verdict = evaluateNamespacePolicyByLookUp(trie_key, flow_key, pod_state);
```

**Decision**:
- ✅ **ALLOW** if source IP (10.0.0.20) is in `ingress_map`
- ❌ **DENY** if source IP not found and pod state = POLICIES_APPLIED

#### Egress Program (tc.v4egress.bpf.c)

**Attachment**: TC ingress on host-side veth (e.g., `veth-be-h`)

**Packet Flow**:
```
Backend Pod ──> veth-be-p ──> veth-be-h ──[TC INGRESS]──> bridge ──> veth-allow-h ──> Client
                                               │
                                               └─> EGRESS PROGRAM
                                                   sees: src=10.0.0.10
                                                         dst=10.0.0.20
```

**Logic** (simplified from actual code):
```c
// Build trie key from DESTINATION IP
trie_key.prefix_len = 32;
trie_key.ip[0] = ip->daddr & 0xff;  // DESTINATION IP (10.0.0.20)
// ... [remaining IP bytes]

// Set egressing pod IP
flow_key.owner_ip = ip->saddr;  // Pod egressing (10.0.0.10)

// Check if DESTINATION IP (10.0.0.20) is in egress_map
verdict = evaluateNamespacePolicyByLookUp(trie_key, flow_key, pod_state);
```

**Decision**:
- ✅ **ALLOW** if destination IP (10.0.0.20) is in `egress_map`
- ❌ **DENY** if destination IP not found and pod state = POLICIES_APPLIED

---

## Practical Setup: Multi-Pod Testing

### Compiling and Attaching eBPF Programs

For a **Backend pod** (10.0.0.10) with Ingress policy "allow from 10.0.0.20":

1. **Compile BOTH programs**:
   ```bash
   clang -O2 -target bpf -c tc.v4ingress.bpf.c -o tc.v4ingress.bpf.o
   clang -O2 -target bpf -c tc.v4egress.bpf.c -o tc.v4egress.bpf.o
   ```

2. **Attach to veth-be-h** (host-side interface):
   ```bash
   # Create clsact qdisc (if not exists)
   sudo tc qdisc add dev veth-be-h clsact
   
   # Ingress program on TC EGRESS (packets TO pod)
   sudo tc filter add dev veth-be-h egress bpf direct-action obj tc.v4ingress.bpf.o sec tc_cls
   
   # Egress program on TC INGRESS (packets FROM pod)
   sudo tc filter add dev veth-be-h ingress bpf direct-action obj tc.v4egress.bpf.o sec tc_cls
   ```

3. **Verify attachment**:
   ```bash
   sudo tc filter show dev veth-be-h egress  # Should show tc.v4ingress.bpf.o
   sudo tc filter show dev veth-be-h ingress # Should show tc.v4egress.bpf.o
   ```

---

## Debugging & Observability

### Inspecting the Implementation

From your node, you can inspect the implementation:

```bash
# See attached eBPF programs
tc filter show dev <pod-veth> ingress
tc filter show dev <pod-veth> egress

# List pinned BPF maps
ls /sys/fs/bpf/

# Dump map contents (with bpftool)
bpftool map dump pinned /sys/fs/bpf/tc/globals/ingress_map
bpftool map dump pinned /sys/fs/bpf/tc/globals/ingress_pod_state_map
bpftool map dump pinned /sys/fs/bpf/tc/globals/aws_conntrack_map

# Check policy agent logs
kubectl logs -n kube-system aws-node -c aws-network-policy-agent

# Check attached programs and their stats
bpftool prog show
bpftool prog dump xlated id <prog_id>

# Watch kernel trace output (eBPF printk messages)
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### BPF Map Configuration for Testing

For **Backend pod** (10.0.0.10) with Ingress policy "allow from 10.0.0.20":

1. **Configure pod state** (both programs):
   ```bash
   # Ingress pod state
   sudo bpftool map update pinned /sys/fs/bpf/tc/globals/ingress_pod_state_map \
     key hex 00 00 00 00 value hex 00  # NETWORK_POLICY_KEY = POLICIES_APPLIED
   sudo bpftool map update pinned /sys/fs/bpf/tc/globals/ingress_pod_state_map \
     key hex 01 00 00 00 value hex 00  # CLUSTER_NETWORK_POLICY_KEY = POLICIES_APPLIED
   
   # Egress pod state (if using egress policies)
   sudo bpftool map update pinned /sys/fs/bpf/tc/globals/egress_pod_state_map \
     key hex 00 00 00 00 value hex 00
   sudo bpftool map update pinned /sys/fs/bpf/tc/globals/egress_pod_state_map \
     key hex 01 00 00 00 value hex 00
   ```

2. **Add allowed source IP to ingress_map**:
   ```bash
   # Allow 10.0.0.20 (0x0a000014 in network byte order = 0x1400000a)
   sudo bpftool map update pinned /sys/fs/bpf/tc/globals/ingress_map \
     key hex 20 00 00 00 0a 00 00 14 \
     value hex fe 00 00 00 00 00 00 00 00 00 00 00 \
           fe 00 00 00 00 00 00 00 00 00 00 00 \
           [... repeated 24 times for MAX_PORT_PROTOCOL]
   ```

### Expected Behavior

**Test from Allowed Client (10.0.0.20)**:
```bash
sudo ip netns exec ns-allowed nc -zv 10.0.0.10 8080
```
Expected trace output:
```
Packet: src=0xa000014 dst=0xa00000a proto=6  ← Ingress sees client→backend
NETWORK_POLICY_TIER: ALLOW                    ← 10.0.0.20 in ingress_map
```
Result: ✅ Connection succeeds

**Test from Denied Client (10.0.0.30)**:
```bash
sudo ip netns exec ns-denied nc -zv 10.0.0.10 8080
```
Expected trace output:
```
Packet: src=0xa00001e dst=0xa00000a proto=6  ← Ingress sees client→backend
NETWORK_POLICY_TIER: DENY                     ← 10.0.0.30 NOT in ingress_map
```
Result: ❌ Connection times out (blocked)

---

## Gotchas & Important Notes

### 1. Drops Happen at TC Layer
- Dropped packets **won't show up in iptables counters**
- You can get them from eBPF program stats or TC statistics
- Use `tc -s filter show dev <veth> ingress` for packet/byte counters

### 2. Host Networking Pods
- Network policies **don't apply** to pods with `hostNetwork: true`
- These pods bypass the veth pair entirely

### 3. Same-Node Pod-to-Pod Traffic
- Still goes through the veth and gets policy-checked
- Never hits the ENI (relevant for packet flow visualization)
- Bridge handles local forwarding

### 4. Agent Dependency on CNI
- The agent needs VPC CNI to be healthy
- If VPC CNI has issues allocating IPs, the policy agent may also misbehave
- Both run in the same `aws-node` pod

### 5. Map Name Truncation
- BPF map names are limited to 15 characters (`BPF_OBJ_NAME_LEN = 16` including null terminator)
- `ingress_pod_state_map` becomes `ingress_pod_sta`
- `aws_conntrack_map` becomes `aws_conntrack_m`
- Use pinned paths for reliable access: `/sys/fs/bpf/tc/globals/<full_name>`

---

## Performance Characteristics

### Why eBPF is Superior to iptables

1. **Lookup Complexity**:
   - iptables: O(n) - linear scan through rules
   - eBPF: O(1) - hash map lookups, O(log n) for LPM trie

2. **Lock Contention**:
   - iptables: Global lock during rule updates
   - eBPF: Lock-free map updates (atomic operations)

3. **Update Atomicity**:
   - iptables: Must rebuild entire chain, brief "policy gap"
   - eBPF: Atomic map updates, no gaps

4. **Scale**:
   - iptables: 1000s of rules = significant latency
   - eBPF: 100,000s of map entries = negligible overhead

5. **JIT Compilation**:
   - eBPF programs are JIT-compiled to native machine code
   - Execute directly in kernel context, no context switches

---

## References

- **Controller Repository**: https://github.com/aws/amazon-network-policy-controller-k8s
- **Agent Repository**: https://github.com/aws/aws-network-policy-agent
- **VPC CNI Repository**: https://github.com/aws/amazon-vpc-cni-k8s
- **Kubernetes NetworkPolicy**: https://kubernetes.io/docs/concepts/services-networking/network-policies/
- **TC (Traffic Control)**: https://man7.org/linux/man-pages/man8/tc.8.html
- **eBPF Documentation**: https://ebpf.io/
