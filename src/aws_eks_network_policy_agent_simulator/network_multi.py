"""Network namespace and interface management for multi-pod scenario."""

import subprocess
import ipaddress
from typing import Optional, List, Dict
from dataclasses import dataclass
from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class PodConfig:
    """Configuration for a single pod."""
    name: str
    namespace: str
    veth_host: str
    veth_pod: str
    ip: str
    role: str  # "backend", "allowed-client", "denied-client"


class MultiPodNetworkManager:
    """Manages network namespaces for a 3-pod scenario.
    
    Simulates:
    - backend pod (service listening on port 8080)
    - allowed-client pod (can connect to backend)
    - denied-client pod (blocked from backend)
    """
    
    def __init__(self, output=None):
        self.host_bridge = "br-sim"
        self.host_bridge_ip = "10.0.0.1/24"
        self.output = output  # Optional TUI output log
        
        # Backend pod - the service being protected
        self.backend = PodConfig(
            name="backend",
            namespace="ns-backend",
            veth_host="veth-be-h",
            veth_pod="veth-be-p",
            ip="10.0.0.10/24",
            role="backend"
        )
        
        # Allowed client - can access backend
        self.allowed_client = PodConfig(
            name="allowed-client",
            namespace="ns-allowed",
            veth_host="veth-allow-h",
            veth_pod="veth-allow-p",
            ip="10.0.0.20/24",
            role="allowed-client"
        )
        
        # Denied client - blocked by network policy
        self.denied_client = PodConfig(
            name="denied-client",
            namespace="ns-denied",
            veth_host="veth-deny-h",
            veth_pod="veth-deny-p",
            ip="10.0.0.30/24",
            role="denied-client"
        )
        
        self.pods = [self.backend, self.allowed_client, self.denied_client]
    
    def _run(self, cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
        """Run a command and return result."""
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )
        
        if check and result.returncode != 0:
            raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{result.stderr}")
        
        return result
    
    def _print(self, message: str) -> None:
        """Print to TUI output log if available, otherwise console."""
        if self.output:
            self.output.write(message)
        else:
            console.print(message)
    
    def cleanup(self) -> None:
        """Clean up existing network setup."""
        self._print("[yellow]Cleaning up old network configuration...[/yellow]")
        
        # Delete all pods
        for pod in self.pods:
            # Delete veth pair
            result = self._run(["ip", "link", "del", pod.veth_host], check=False)
            if result.returncode == 0:
                self._print(f"[cyan]$ ip link del {pod.veth_host}[/cyan]")
            
            # Delete namespace
            result = self._run(["ip", "netns", "del", pod.namespace], check=False)
            if result.returncode == 0:
                self._print(f"[cyan]$ ip netns del {pod.namespace}[/cyan]")
        
        # Delete bridge
        result = self._run(["ip", "link", "del", self.host_bridge], check=False)
        if result.returncode == 0:
            self._print(f"[cyan]$ ip link del {self.host_bridge}[/cyan]")
        
        self._print("")
    
    def create_bridge(self) -> bool:
        """Create a bridge to connect all pods."""
        self._print("[yellow]Creating bridge...[/yellow]")
        
        try:
            self._run(["ip", "link", "add", self.host_bridge, "type", "bridge"])
            self._print(f"[cyan]$ ip link add {self.host_bridge} type bridge[/cyan]")
            
            self._run(["ip", "addr", "add", self.host_bridge_ip, "dev", self.host_bridge])
            self._print(f"[cyan]$ ip addr add {self.host_bridge_ip} dev {self.host_bridge}[/cyan]")
            
            self._run(["ip", "link", "set", self.host_bridge, "up"])
            self._print(f"[cyan]$ ip link set {self.host_bridge} up[/cyan]")
            self._print("")
            
            return True
            
        except Exception as e:
            self._print(f"[red][ERROR] Failed to create bridge: {e}[/red]")
            return False
    
    def setup_pod(self, pod: PodConfig) -> bool:
        """Setup a single pod with network namespace."""
        self._print(f"[yellow]Setting up {pod.name}...[/yellow]")
        
        try:
            # Create veth pair
            self._run([
                "ip", "link", "add",
                pod.veth_host, "type", "veth",
                "peer", "name", pod.veth_pod
            ])
            self._print(f"[cyan]$ ip link add {pod.veth_host} type veth peer name {pod.veth_pod}[/cyan]")
            
            # Connect host side to bridge
            self._run(["ip", "link", "set", pod.veth_host, "master", self.host_bridge])
            self._print(f"[cyan]$ ip link set {pod.veth_host} master {self.host_bridge}[/cyan]")
            
            self._run(["ip", "link", "set", pod.veth_host, "up"])
            self._print(f"[cyan]$ ip link set {pod.veth_host} up[/cyan]")
            
            # Create namespace
            self._run(["ip", "netns", "add", pod.namespace])
            self._print(f"[cyan]$ ip netns add {pod.namespace}[/cyan]")
            
            # Move pod side to namespace
            self._run(["ip", "link", "set", pod.veth_pod, "netns", pod.namespace])
            self._print(f"[cyan]$ ip link set {pod.veth_pod} netns {pod.namespace}[/cyan]")
            
            # Configure inside namespace
            self._run(["ip", "netns", "exec", pod.namespace,
                      "ip", "link", "set", "lo", "up"])
            self._run(["ip", "netns", "exec", pod.namespace,
                      "ip", "link", "set", pod.veth_pod, "up"])
            self._run(["ip", "netns", "exec", pod.namespace,
                      "ip", "addr", "add", pod.ip, "dev", pod.veth_pod])
            self._print(f"[cyan]$ ip netns exec {pod.namespace} ip addr add {pod.ip} dev {pod.veth_pod}[/cyan]")
            
            # Add default route to bridge
            bridge_ip = self.host_bridge_ip.split('/')[0]
            self._run(["ip", "netns", "exec", pod.namespace,
                      "ip", "route", "add", "default", "via", bridge_ip])
            self._print(f"[cyan]$ ip netns exec {pod.namespace} ip route add default via {bridge_ip}[/cyan]")
            self._print("")
            
            return True
            
        except Exception as e:
            self._print(f"[red][ERROR] Failed: {pod.name}: {e}[/red]")
            return False
    
    def setup_network(self) -> bool:
        """Setup complete multi-pod network."""
        # Cleanup first
        self.cleanup()
        
        # Create bridge
        if not self.create_bridge():
            return False
        
        # Setup each pod
        for pod in self.pods:
            if not self.setup_pod(pod):
                return False
        
        return True
    
    def show_network_summary(self) -> None:
        """Display network configuration summary."""
        table = Table(title="Pod Network Configuration")
        table.add_column("Pod", style="cyan")
        table.add_column("Role", style="yellow")
        table.add_column("IP Address", style="green")
        table.add_column("Namespace", style="blue")
        
        for pod in self.pods:
            table.add_row(pod.name, pod.role, pod.ip, pod.namespace)
        
        console.print(table)
    
    def test_connectivity(self, from_pod: str, to_pod: str) -> bool:
        """Test connectivity between two pods."""
        # Find pod configs
        src = next((p for p in self.pods if p.name == from_pod), None)
        dst = next((p for p in self.pods if p.name == to_pod), None)
        
        if not src or not dst:
            console.print(f"[red][ERROR] Invalid pod names[/red]")
            return False
        
        target_ip = dst.ip.split('/')[0]
        console.print(f"\n[blue]Testing: {src.name} -> {dst.name} ({target_ip})[/blue]")
        
        try:
            result = self._run([
                "ip", "netns", "exec", src.namespace,
                "ping", "-c", "2", "-W", "1", target_ip
            ])
            
            console.print("[green][OK] Connectivity successful[/green]")
            return True
            
        except Exception as e:
            console.print(f"[yellow][WARN] Connectivity failed (expected if policy blocks)[/yellow]")
            return False
    
    def start_backend_server(self, port: int = 8080) -> subprocess.Popen:
        """Start a TCP server in the backend pod."""
        console.print(f"\n[blue]Starting TCP server in backend pod on port {port}...[/blue]")
        
        # Use nc (netcat) as a simple TCP listener
        proc = subprocess.Popen([
            "ip", "netns", "exec", self.backend.namespace,
            "nc", "-l", "-k", "-p", str(port)
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        console.print(f"[green][OK] Backend server listening on {self.backend.ip.split('/')[0]}:{port}[/green]")
        return proc
    
    def test_tcp_connection(self, from_pod: str, port: int = 8080, timeout: int = 2) -> bool:
        """Test TCP connection to backend."""
        src = next((p for p in self.pods if p.name == from_pod), None)
        if not src:
            console.print(f"[red][ERROR] Invalid pod name: {from_pod}[/red]")
            return False
        
        target_ip = self.backend.ip.split('/')[0]
        console.print(f"\n[blue]Testing TCP: {src.name} -> backend:{port}[/blue]")
        console.print(f"[dim]Command: ip netns exec {src.namespace} nc -zv -w {timeout} {target_ip} {port}[/dim]")
        
        try:
            result = self._run([
                "ip", "netns", "exec", src.namespace,
                "nc", "-zv", "-w", str(timeout), target_ip, str(port)
            ], check=False)
            
            if result.returncode == 0:
                console.print("[green][OK] TCP connection successful[/green]")
                return True
            else:
                console.print("[red][ERROR] TCP connection failed (blocked by policy)[/red]")
                return False
                
        except Exception as e:
            console.print(f"[red][ERROR] Error testing connection: {e}[/red]")
            return False
