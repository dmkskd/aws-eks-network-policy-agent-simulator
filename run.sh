#!/bin/bash
# Run eBPF Manager with uv
# Assumes uv is in PATH (either via /usr/local/bin or ~/.local/bin)

exec sudo uv run python -m aws_eks_network_policy_agent_simulator "$@"
