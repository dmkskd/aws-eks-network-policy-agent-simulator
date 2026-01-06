"""Network namespace and interface management."""

import subprocess
import ipaddress
from typing import Optional
from rich.console import Console
from rich.table import Table

console = Console()


class NetworkManager:
    """Manages network namespaces and virtual interfaces."""
    
    def __init__(self):
        self.host_iface = "veth-host"
        self.pod_iface = "veth-client"
        self.namespace = "sim-pod"
        self.host_ip = "10.0.0.1/24"
        self.pod_ip = "10.0.0.2/24"
    
    def _run(self, cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
        """Run a command and return result."""
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )
        
        if check and result.returncode != 0:
            raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{result.stderr}")
        
        return result
    
    def cleanup(self) -> None:
        """Clean up existing network setup."""
        console.print("\n[yellow]Cleaning up old network configuration...[/yellow]")
        
        # Delete veth pair
        result = self._run(["ip", "link", "del", self.host_iface], check=False)
        if result.returncode == 0:
            console.print(f"  → Removed {self.host_iface}")
        else:
            console.print(f"  → {self.host_iface} did not exist")
        
        # Delete namespace
        result = self._run(["ip", "netns", "del", self.namespace], check=False)
        if result.returncode == 0:
            console.print(f"  → Removed namespace {self.namespace}")
        else:
            console.print(f"  → Namespace {self.namespace} did not exist")
        
        console.print("[green][OK] Cleanup complete[/green]")
    
    def create_veth_pair(self) -> bool:
        """Create virtual ethernet pair."""
        console.print(f"\n[blue]Creating veth pair: {self.host_iface} <-> {self.pod_iface}[/blue]")
        
        try:
            self._run([
                "ip", "link", "add",
                self.host_iface, "type", "veth",
                "peer", "name", self.pod_iface
            ])
            console.print("[green][OK] Veth pair created[/green]")
            
            # Verify
            result = self._run(["ip", "link", "show", self.host_iface])
            console.print(f"[dim]{result.stdout.strip()}[/dim]")
            return True
            
        except Exception as e:
            console.print(f"[red][ERROR] Failed to create veth pair: {e}[/red]")
            return False
    
    def configure_host_side(self) -> bool:
        """Configure host side of veth pair."""
        console.print(f"\n[blue]Configuring host side ({self.host_iface})...[/blue]")
        
        try:
            # Bring up interface
            self._run(["ip", "link", "set", self.host_iface, "up"])
            console.print("  → Interface UP")
            
            # Assign IP
            self._run(["ip", "addr", "add", self.host_ip, "dev", self.host_iface])
            console.print(f"  → IP assigned: {self.host_ip}")
            
            # Verify
            result = self._run(["ip", "-4", "addr", "show", self.host_iface])
            console.print(f"[dim]{result.stdout.strip()}[/dim]")
            console.print("[green][OK] Host side configured[/green]")
            return True
            
        except Exception as e:
            console.print(f"[red][ERROR] Failed to configure host: {e}[/red]")
            return False
    
    def configure_pod_side(self) -> bool:
        """Configure pod side in network namespace."""
        console.print(f"\n[blue]Configuring pod side (namespace: {self.namespace})...[/blue]")
        
        try:
            # Create namespace
            self._run(["ip", "netns", "add", self.namespace])
            console.print(f"  → Namespace '{self.namespace}' created")
            
            # Move interface to namespace
            self._run(["ip", "link", "set", self.pod_iface, "netns", self.namespace])
            console.print(f"  → {self.pod_iface} moved to namespace")
            
            # Configure inside namespace
            self._run(["ip", "netns", "exec", self.namespace, 
                      "ip", "link", "set", self.pod_iface, "up"])
            console.print("  → Interface UP")
            
            self._run(["ip", "netns", "exec", self.namespace,
                      "ip", "addr", "add", self.pod_ip, "dev", self.pod_iface])
            console.print(f"  → IP assigned: {self.pod_ip}")
            
            # Verify
            result = self._run(["ip", "netns", "exec", self.namespace,
                               "ip", "-4", "addr", "show", self.pod_iface])
            console.print(f"[dim]{result.stdout.strip()}[/dim]")
            console.print("[green][OK] Pod side configured[/green]")
            return True
            
        except Exception as e:
            console.print(f"[red][ERROR] Failed to configure pod: {e}[/red]")
            return False
    
    def test_connectivity(self) -> bool:
        """Test connectivity between pod and host."""
        console.print("\n[blue]Testing connectivity...[/blue]")
        console.print(f"[dim]Pinging {self.host_ip.split('/')[0]} from namespace[/dim]")
        
        try:
            result = self._run([
                "ip", "netns", "exec", self.namespace,
                "ping", "-c", "2", "-W", "1", self.host_ip.split('/')[0]
            ])
            
            console.print("[green][OK] Connectivity test passed[/green]")
            console.print(f"[dim]{result.stdout}[/dim]")
            return True
            
        except Exception as e:
            console.print(f"[red][ERROR] Connectivity test failed[/red]")
            console.print(str(e))
            return False
    
    def setup_network(self) -> bool:
        """Complete network setup."""
        self.cleanup()
        
        if not self.create_veth_pair():
            return False
        
        if not self.configure_host_side():
            return False
        
        if not self.configure_pod_side():
            return False
        
        if not self.test_connectivity():
            return False
        
        console.print("\n[green bold][OK] Network setup complete[/green bold]")
        return True
    
    def show_status(self) -> None:
        """Display current network configuration."""
        table = Table(title="Network Configuration")
        table.add_column("Component", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Host Interface", self.host_iface)
        table.add_row("Host IP", self.host_ip)
        table.add_row("Pod Interface", self.pod_iface)
        table.add_row("Pod IP", self.pod_ip)
        table.add_row("Namespace", self.namespace)
        
        console.print(table)
