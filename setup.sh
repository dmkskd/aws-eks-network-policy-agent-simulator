#!/bin/bash
# Setup script for eBPF Manager
# Installs all required dependencies and tools
# Supports: Ubuntu/Debian-based systems

set -e

echo "=== eBPF Manager Setup ==="
echo ""

# Check if running on Ubuntu/Debian
if ! command -v apt-get &> /dev/null; then
    echo "Error: This setup script requires Ubuntu/Debian (apt-get not found)"
    echo "For other distributions, please install dependencies manually:"
    echo "  - clang, llvm, libbpf-dev, iproute2, bpftool, netcat, xclip"
    echo "  - linux-headers for your kernel"
    echo "  - Python 3.8+ with pip"
    exit 1
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Error: Please run as root (use sudo)"
    exit 1
fi

# Detect the real user and home directory
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo ~$REAL_USER)

echo "1. Checking Python..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo "   ✓ $PYTHON_VERSION found"
else
    echo "   Installing python3..."
    apt-get update
    apt-get install -y python3 python3-pip
fi

echo ""
echo "2. Installing eBPF toolchain and dependencies..."

# Required packages from README
PACKAGES=(
    clang
    llvm
    libbpf-dev
    iproute2
    bpftool
    netcat-openbsd
    linux-headers-$(uname -r)
)

# Check which packages are missing
MISSING=()
for pkg in "${PACKAGES[@]}"; do
    if ! dpkg -l | grep -q "^ii  $pkg"; then
        MISSING+=("$pkg")
    fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
    echo "   Installing: ${MISSING[*]}"
    apt-get update
    apt-get install -y "${MISSING[@]}"
    echo "   ✓ All packages installed"
else
    echo "   ✓ All packages already installed"
fi

echo ""
echo "3. Installing uv (Python package manager)..."
if command -v uv &> /dev/null; then
    echo "   ✓ uv already installed"
else
    echo "   Installing uv for user: $REAL_USER"
    sudo -u $REAL_USER bash -c 'curl -LsSf https://astral.sh/uv/install.sh | sh'
    echo "   ✓ uv installed"
fi

# Ensure uv is in PATH by creating a symlink in /usr/local/bin
echo ""
echo "4. Configuring uv in system PATH..."
if [ -f "$REAL_HOME/.local/bin/uv" ]; then
    if [ ! -L /usr/local/bin/uv ]; then
        ln -sf "$REAL_HOME/.local/bin/uv" /usr/local/bin/uv
        echo "   ✓ Created symlink: /usr/local/bin/uv -> $REAL_HOME/.local/bin/uv"
    else
        echo "   ✓ Symlink already exists"
    fi
else
    echo "   ⚠ Warning: uv not found at $REAL_HOME/.local/bin/uv"
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "To run the eBPF manager:"
echo "  ./run.sh"
echo ""
echo "Or manually:"
echo "  sudo uv run python -m aws_eks_network_policy_agent_simulator"
echo ""
echo "Project: aws-eks-network-policy-agent-simulator"
echo "Note: uv is now available system-wide via /usr/local/bin/uv"
