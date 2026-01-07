# AWS EKS VPC CNI Network Policy Simulator

## Overview

For anyone curious on how Network Policies are implemented in AWS EKS using the AWS VPC CNI plugin, this repo gives a 'stripped down' version of the various components.

At a very high level:
- an ebpf program is attached to to the [ingress](ebpf/c/tc.v4ingress.bpf.c) / [egress](ebpf/c/tc.v4egress.bpf.c) path on a veth tc extension point
- pod ip addresses are dynamically published to a ebpf maps consumed by those ebpf programs
- the ebpf programs would ALLOW, DENY, PASS the packet depending on the data in the ebpf maps

## Quick Start

### Prerequisites

```bash
# Must run as root
sudo ./setup.sh
```

### Launch TUI

Must run as root

```bash
sudo ./run.sh
```


## How It Works


## License

- AWS VPC CNI source: Apache 2.0
- Modifications: Same (Apache 2.0)

## References

- [AWS Network Policy Agent](https://github.com/aws/aws-network-policy-agent)
- [eBPF TC Documentation](https://docs.kernel.org/bpf/prog_cgroup_sockopt.html)
- [BPF Type Format (BTF)](https://www.kernel.org/doc/html/latest/bpf/btf.html)
