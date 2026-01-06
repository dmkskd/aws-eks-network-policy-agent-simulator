"""BPF program loading and map management."""

import subprocess
import struct
import socket
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table

from .environment import EnvironmentManager

console = Console()


class BPFManager:
    """Manages BPF program loading and map operations."""
    
    def __init__(self, interface: str = "veth-host", source_file: Optional[Path] = None):
        self.interface = interface
        self.program_id: Optional[int] = None
        self.map_id: Optional[int] = None
        
        # Discover or use provided source file
        if source_file:
            self.source_file = source_file
            self.egress_source_file = None  # Manual mode - single file only
        else:
            self.source_file = self._discover_source_file()
            # Also discover egress file if ingress is found
            if self.source_file and "ingress" in str(self.source_file):
                self.egress_source_file = self._discover_egress_file()
            else:
                self.egress_source_file = None
        
        self.obj_file: Optional[Path] = None
        self.egress_obj_file: Optional[Path] = None
        self.env_mgr = EnvironmentManager()
    
    def _discover_source_file(self) -> Optional[Path]:
        """Auto-discover BPF source file in current directory."""
        cwd = Path.cwd()
        
        # Priority order: AWS VPC CNI source > test_policy.c > any .c file
        # Check ebpf/c/ subdirectory first (AWS structure)
        c_dir = cwd / "ebpf" / "c"
        aws_source = c_dir / "tc.v4ingress.bpf.c"
        if aws_source.exists():
            console.print(f"[dim]Using AWS VPC CNI source: {aws_source}[/dim]")
            return aws_source
        
        # Fallback to old location
        aws_source_old = cwd / "tc.v4ingress.bpf.c"
        if aws_source_old.exists():
            console.print(f"[dim]Using AWS VPC CNI source: {aws_source_old.name}[/dim]")
            return aws_source_old
        
        test_policy = cwd / "test_policy.c"
        if test_policy.exists():
            console.print(f"[dim]Using: test_policy.c[/dim]")
            return test_policy
        
        # Look for any .c files in ebpf/c/ dir
        if c_dir.exists():
            c_files = list(c_dir.glob("*.c"))
            if c_files:
                console.print(f"[dim]Auto-discovered in ebpf/c/: {c_files[0].name}[/dim]")
                return c_files[0]
        
        # Look for any .c files in current dir
        c_files = list(cwd.glob("*.c"))
        
        if len(c_files) == 1:
            console.print(f"[dim]Auto-discovered: {c_files[0].name}[/dim]")
            return c_files[0]
        elif len(c_files) > 1:
            console.print(f"[yellow]Multiple .c files found: {[f.name for f in c_files]}[/yellow]")
            return c_files[0]
        else:
            console.print("[yellow]No .c files found in current directory or ebpf/c/ subdirectory[/yellow]")
            return None
    
    def _discover_egress_file(self) -> Optional[Path]:
        """Discover egress source file if ingress file is found."""
        if not self.source_file:
            return None
        
        # Look for egress file in same directory as ingress
        egress_file = self.source_file.parent / "tc.v4egress.bpf.c"
        if egress_file.exists():
            console.print(f"[dim]Found egress source: {egress_file.name}[/dim]")
            return egress_file
        else:
            console.print(f"[yellow]Egress source not found: {egress_file}[/yellow]")
            return None
    
    def compile(self) -> bool:
        """Compile BPF source to object file."""
        if not self.source_file or not self.source_file.exists():
            console.print(f"[red][ERROR] Source file not found: {self.source_file}[/red]")
            return False
        
        # Check for vmlinux.h if using AWS source
        if "tc.v4ingress" in str(self.source_file) or "tc.v4egress" in str(self.source_file):
            vmlinux_h = self.source_file.parent / "vmlinux.h"
            if not vmlinux_h.exists():
                console.print(f"[yellow][WARN] vmlinux.h not found at {vmlinux_h}[/yellow]")
                console.print("[yellow]Generating vmlinux.h from kernel BTF...[/yellow]")
                try:
                    subprocess.run(
                        ["bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"],
                        stdout=open(vmlinux_h, "w"),
                        check=True
                    )
                    console.print(f"[green][OK] Generated vmlinux.h[/green]")
                except Exception as e:
                    console.print(f"[red][ERROR] Failed to generate vmlinux.h: {e}[/red]")
                    return False
        
        result = self.env_mgr.compile_bpf_program(self.source_file)
        
        if result:
            self.obj_file = result
            console.print(f"[green][OK] Compiled ingress program: {self.obj_file.name}[/green]")
        else:
            return False
        
        # Also compile egress program if available
        if self.egress_source_file:
            console.print(f"\n[blue]Compiling egress program...[/blue]")
            egress_result = self.env_mgr.compile_bpf_program(self.egress_source_file)
            if egress_result:
                self.egress_obj_file = egress_result
                console.print(f"[green][OK] Compiled egress program: {self.egress_obj_file.name}[/green]")
            else:
                console.print("[yellow][WARN] Egress compilation failed, continuing with ingress only[/yellow]")
        
        return True
    
    def _run(self, cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
        """Run a command and return result."""
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )
        
        if check and result.returncode != 0:
            error_msg = f"Command failed: {' '.join(cmd)}\n"
            if result.stderr:
                error_msg += f"STDERR: {result.stderr}"
            if result.stdout:
                error_msg += f"\nSTDOUT: {result.stdout}"
            raise RuntimeError(error_msg)
        
        return result
    
    def setup_qdisc(self) -> bool:
        """Setup clsact qdisc on interface."""
        console.print(f"\n[blue]Setting up TC qdisc on {self.interface}...[/blue]")
        
        # Check if already exists
        result = self._run(["tc", "qdisc", "show", "dev", self.interface], check=False)
        
        if "clsact" in result.stdout:
            console.print("[green][OK] clsact qdisc already exists[/green]")
            return True
        
        try:
            self._run(["tc", "qdisc", "add", "dev", self.interface, "clsact"])
            console.print("[green][OK] clsact qdisc created[/green]")
            return True
        except Exception as e:
            console.print(f"[red][ERROR] Failed to setup qdisc: {e}[/red]")
            return False
    
    def cleanup_filters(self) -> None:
        """Remove existing BPF filters."""
        console.print("[yellow]Cleaning old BPF filters...[/yellow]")
        result = self._run(
            ["tc", "filter", "del", "dev", self.interface, "ingress"],
            check=False
        )
        
        if result.returncode == 0:
            console.print("  → Old filters removed")
        else:
            console.print("  → No previous filters found")
    
    def cleanup_pinned_maps(self) -> None:
        """Remove pinned BPF maps to ensure clean state.
        
        Pinned maps persist across program loads. This clears them
        to prevent stale entries from affecting new policy evaluations.
        """
        console.print("[yellow]Cleaning pinned BPF maps...[/yellow]")
        
        map_names = [
            "ingress_map",
            "cp_ingress_map", 
            "ingress_pod_state_map",
            "aws_conntrack_map"
        ]
        
        for map_name in map_names:
            # Maps are pinned in /sys/fs/bpf/ by default
            map_path = f"/sys/fs/bpf/{map_name}"
            result = self._run(["rm", "-f", map_path], check=False)
            
            if result.returncode == 0:
                console.print(f"  → Removed pinned map: {map_name}")
            else:
                console.print(f"  → Map {map_name} not found (ok)")
        
        console.print("[green][OK] Map cleanup complete[/green]")
    
    def load_program(self, obj_file: Optional[Path] = None) -> bool:
        """Load BPF program and attach to HOST side of veth interface.
        
        Note: The BPF program attaches to the HOST side of the veth pair (e.g., veth-be-h)
        to inspect traffic ENTERING the backend pod. Communication with the pod happens
        via BPF maps (ingress_map, pod_state_map, etc.).
        
        Args:
            obj_file: Optional object file path. If not provided, uses self.obj_file
        """
        if obj_file:
            self.obj_file = obj_file
        
        if not self.obj_file or not self.obj_file.exists():
            console.print(f"[red][ERROR] Object file not found: {self.obj_file}[/red]")
            console.print("[yellow][WARN] Compile the program first[/yellow]")
            return False
        
        console.print(f"\n[blue]Attaching BPF to HOST side: {self.interface}[/blue]")
        console.print(f"[dim]Program: {self.obj_file.name}[/dim]")
        
        try:
            # Detect section name based on source file
            section = "tc_cls"  # AWS VPC CNI uses this section
            if "test_policy" in str(self.obj_file):
                section = "classifier"  # Old test policy might use this
            
            # AWS Network Policy: Ingress program attaches to TC EGRESS (packets TO pod)
            direction = "egress" if "ingress" in str(self.obj_file) else "ingress"
            
            cmd = [
                "tc", "filter", "add",
                "dev", self.interface,
                direction,
                "bpf", "da",
                "obj", str(self.obj_file),
                "sec", section
            ]
            
            console.print(f"[dim]Command: {' '.join(cmd)}[/dim]")
            console.print(f"[dim]Section: {section}, Direction: {direction}[/dim]")
            
            result = self._run(cmd, check=False)
            
            if result.returncode != 0:
                console.print("[red][ERROR] TC filter failed to load BPF program[/red]")
                if result.stderr:
                    console.print(f"[red]Error output:[/red]")
                    for line in result.stderr.strip().split('\n'):
                        console.print(f"  {line}")
                if result.stdout:
                    console.print(f"[yellow]Additional output:[/yellow]")
                    for line in result.stdout.strip().split('\n'):
                        console.print(f"  {line}")
                return False
            
            console.print("[green][OK] BPF program attached to interface[/green]")
            
            # Initialize pod state maps for AWS VPC CNI
            if "tc.v4ingress" in str(self.obj_file):
                console.print("[dim]Initializing pod state maps for AWS VPC CNI...[/dim]")
                if self.initialize_pod_state_maps():
                    console.print("[green][OK] Pod state maps initialized[/green]")
                else:
                    console.print("[yellow][WARN] Map initialization skipped (may not be needed)[/yellow]")
                
                # Cache ingress_map ID for later use
                console.print("[dim]Caching ingress_map ID...[/dim]")
                self.map_id = self.find_map("ingress_map")
                if self.map_id:
                    console.print(f"[green][OK] Cached ingress_map ID: {self.map_id}[/green]")
            
            return True
            
        except Exception as e:
            console.print(f"[red][ERROR] Failed to load program: {e}[/red]")
            return False
    
    def verify_program(self) -> bool:
        """Verify program is loaded and get its ID."""
        console.print("\n[blue]Verifying BPF program...[/blue]")
        
        try:
            # Determine direction based on program type
            direction = "egress" if "ingress" in str(self.obj_file) else "ingress"
            
            # Get filter info
            result = self._run(["tc", "filter", "show", "dev", self.interface, direction])
            console.print(f"[dim]TC Filter Output ({direction}):[/dim]")
            console.print(f"[dim]{result.stdout}[/dim]")
            
            # Extract program ID
            for line in result.stdout.split('\n'):
                if 'id' in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == 'id' and i + 1 < len(parts):
                            self.program_id = int(parts[i + 1])
                            break
            
            if self.program_id:
                console.print(f"[green][OK] Program loaded with ID: {self.program_id}[/green]")
                
                # Get detailed program info
                result = self._run(["bpftool", "prog", "show", "id", str(self.program_id)])
                console.print(f"[dim]{result.stdout}[/dim]")
                
                return True
            else:
                console.print("[red][ERROR] Could not determine program ID[/red]")
                return False
                
        except Exception as e:
            console.print(f"[red][ERROR] Verification failed: {e}[/red]")
            return False
    
    def find_map(self, map_name: str = "ingress_map") -> Optional[int]:
        """Find BPF map by name and return its ID.
        
        Note: BPF map names are truncated to 15 characters (BPF_OBJ_NAME_LEN).
        """
        try:
            result = self._run(["bpftool", "map", "list"])
            
            # BPF map names are limited to 15 chars, so truncate for comparison
            search_name = map_name[:15]
            
            lines = result.stdout.split('\n')
            for i, line in enumerate(lines):
                # Look for map name match (may be truncated to 15 chars)
                # Format: "123: type  name exact_name  flags ..."
                if f" name {search_name} " in line or f" name {search_name}\t" in line or line.endswith(f" name {search_name}"):
                    # Map ID is at the start of the line
                    if ':' in line:
                        map_id = int(line.split(':')[0])
                        if map_name == "ingress_map":
                            self.map_id = map_id
                        console.print(f"[green][OK] Found map '{map_name}' (as '{search_name}') with ID: {map_id}[/green]")
                        return map_id
            
            console.print(f"[red][ERROR] Map '{map_name}' not found[/red]")
            return None
            
        except Exception as e:
            console.print(f"[red][ERROR] Error finding map: {e}[/red]")
            return None
    
    def initialize_pod_state_maps(self) -> bool:
        """Initialize the ingress_pod_state_map and egress_pod_state_map with default values.
        
        This is required for the AWS VPC CNI BPF program to work.
        - Ingress: Sets to POLICIES_APPLIED (0) for deny-by-default on incoming connections
        - Egress: Sets to DEFAULT_ALLOW (1) to permit all outbound connections
        """
        console.print("\n[blue]Initializing pod state maps...[/blue]")
        
        # Initialize ingress pod state map
        ingress_pod_state_map_id = self.find_map("ingress_pod_state_map")
        if not ingress_pod_state_map_id:
            console.print("[yellow][WARN] Ingress pod state map not found[/yellow]")
        else:
            try:
                # NETWORK_POLICY_KEY = 0, state = POLICIES_APPLIED (0)
                cmd1 = [
                    "bpftool", "map", "update",
                    "id", str(ingress_pod_state_map_id),
                    "key", "hex", "00", "00", "00", "00",
                    "value", "hex", "00"
                ]
                console.print(f"[dim]Ingress: Setting NETWORK_POLICY_KEY=0 to POLICIES_APPLIED[/dim]")
                self._run(cmd1)
                
                # CLUSTER_NETWORK_POLICY_KEY = 1, state = POLICIES_APPLIED (0)
                cmd2 = [
                    "bpftool", "map", "update",
                    "id", str(ingress_pod_state_map_id),
                    "key", "hex", "01", "00", "00", "00",
                    "value", "hex", "00"
                ]
                console.print(f"[dim]Ingress: Setting CLUSTER_NETWORK_POLICY_KEY=1 to POLICIES_APPLIED[/dim]")
                self._run(cmd2)
                
                console.print("[green][OK] Ingress pod state: POLICIES_APPLIED (deny-by-default)[/green]")
            except Exception as e:
                console.print(f"[red][ERROR] Failed to initialize ingress pod state: {e}[/red]")
                return False
        
        # Initialize egress pod state map (allow all outbound by default)
        egress_pod_state_map_id = self.find_map("egress_pod_state_map")
        if egress_pod_state_map_id:
            try:
                # NETWORK_POLICY_KEY = 0, state = DEFAULT_ALLOW (1)
                cmd1 = [
                    "bpftool", "map", "update",
                    "id", str(egress_pod_state_map_id),
                    "key", "hex", "00", "00", "00", "00",
                    "value", "hex", "01"
                ]
                console.print(f"[dim]Egress: Setting NETWORK_POLICY_KEY=0 to DEFAULT_ALLOW[/dim]")
                self._run(cmd1)
                
                # CLUSTER_NETWORK_POLICY_KEY = 1, state = DEFAULT_ALLOW (1)
                cmd2 = [
                    "bpftool", "map", "update",
                    "id", str(egress_pod_state_map_id),
                    "key", "hex", "01", "00", "00", "00",
                    "value", "hex", "01"
                ]
                console.print(f"[dim]Egress: Setting CLUSTER_NETWORK_POLICY_KEY=1 to DEFAULT_ALLOW[/dim]")
                self._run(cmd2)
                
                console.print("[green][OK] Egress pod state: DEFAULT_ALLOW (permit all outbound)[/green]")
            except Exception as e:
                console.print(f"[yellow][WARN] Failed to initialize egress pod state: {e}[/yellow]")
        else:
            console.print("[dim]Egress pod state map not found (egress program may not be loaded)[/dim]")
        
        return True
    
    def enforce_policies(self) -> bool:
        """Enable strict policy enforcement (deny-by-default with explicit allows).
        
        Changes pod_state from DEFAULT_ALLOW (1) to POLICIES_APPLIED (0).
        After this, only IPs explicitly added to ingress_map will be allowed.
        """
        console.print("\n[blue]Enabling strict policy enforcement...[/blue]")
        
        # Find the pod state map
        pod_state_map_id = self.find_map("ingress_pod_state_map")
        if not pod_state_map_id:
            console.print("[red][ERROR] Pod state map not found[/red]")
            return False
        
        try:
            # NETWORK_POLICY_KEY = 0, state = POLICIES_APPLIED (0) = deny by default
            cmd = [
                "bpftool", "map", "update",
                "id", str(pod_state_map_id),
                "key", "hex", "00", "00", "00", "00",
                "value", "hex", "00"
            ]
            console.print(f"[dim]Setting NETWORK_POLICY_KEY=0 to POLICIES_APPLIED (deny-by-default)[/dim]")
            self._run(cmd)
            
            console.print("[green][OK] Strict policy enforcement enabled[/green]")
            console.print("[yellow]  Only explicitly allowed IPs can connect[/yellow]")
            return True
            
        except Exception as e:
            console.print(f"[red][ERROR] Failed to enforce policies: {e}[/red]")
            return False
    
    def add_allowed_ip(self, ip_addr: str) -> bool:
        """Add an IP address to the ingress_map (AWS VPC CNI LPM trie format).
        
        The ingress_map uses LPM trie with:
        - Key: struct lpm_trie_key { u32 prefixlen; u32 ip; }
        - Value: array of struct lpm_trie_val (protocol, start_port, end_port)
        """
        if not self.map_id:
            console.print("[dim]Map ID not cached, searching for ingress_map...[/dim]")
            self.map_id = self.find_map("ingress_map")
            if not self.map_id:
                console.print("[red][ERROR] Could not find ingress_map[/red]")
                return False
        
        console.print(f"\n[blue]Adding IP to ingress_map (ID: {self.map_id}): {ip_addr}[/blue]")
        
        try:
            # Convert IP to 32-bit integer in network byte order
            ip_bytes = socket.inet_aton(ip_addr)
            ip_int = struct.unpack('!I', ip_bytes)[0]
            
            # LPM trie key: prefix_len (32 for /32) + IP (4 bytes in network order)
            # Key format: [prefix_len: 4 bytes] [ip: 4 bytes]
            prefix_len = 32  # /32 for exact IP match
            
            # Convert to hex bytes for bpftool
            key_hex = []
            # prefix_len as 4-byte little-endian
            key_hex.extend([f'{(prefix_len >> (8*i)) & 0xff:02x}' for i in range(4)])
            # IP as 4-byte big-endian (network order)
            key_hex.extend([f'{b:02x}' for b in ip_bytes])
            
            console.print(f"[dim]Key (prefixlen=32, ip={ip_addr}): {' '.join(key_hex)}[/dim]")
            
            # Value: array of lpm_trie_val structs
            # For simplicity, add one entry: ANY_IP_PROTOCOL (254), ANY_PORT (0), end_port (0)
            # struct lpm_trie_val { u32 protocol; u32 start_port; u32 end_port; } = 12 bytes
            # We need MAX_PORT_PROTOCOL (24) entries = 24 * 12 = 288 bytes
            
            # First entry: ANY_IP_PROTOCOL, ANY_PORT (allow all protocols/ports)
            value_hex = []
            # protocol = 254 (ANY_IP_PROTOCOL) - 4 bytes little-endian
            value_hex.extend(['fe', '00', '00', '00'])
            # start_port = 0 (ANY_PORT) - 4 bytes little-endian  
            value_hex.extend(['00', '00', '00', '00'])
            # end_port = 0 - 4 bytes little-endian
            value_hex.extend(['00', '00', '00', '00'])
            
            # Fill rest with RESERVED_IP_PROTOCOL (255) to mark as unused
            for i in range(23):  # 23 more entries (total 24)
                value_hex.extend(['ff', '00', '00', '00'])  # protocol = 255 (RESERVED)
                value_hex.extend(['00', '00', '00', '00'])  # start_port = 0
                value_hex.extend(['00', '00', '00', '00'])  # end_port = 0
            
            cmd = [
                "bpftool", "map", "update",
                "id", str(self.map_id),
                "key", "hex"] + key_hex + [
                "value", "hex"] + value_hex
            
            console.print(f"[dim]Adding LPM trie entry (ANY_PROTOCOL/ANY_PORT)[/dim]")
            self._run(cmd)
            
            console.print(f"[green][OK] IP {ip_addr}/32 added to ingress_map[/green]")
            return True
            
        except Exception as e:
            console.print(f"[red][ERROR] Failed to add IP: {e}[/red]")
            import traceback
            console.print(f"[red]{traceback.format_exc()}[/red]")
            return False
    
    def remove_allowed_ip(self, ip_addr: str) -> bool:
        """Remove an IP address from the ingress_map."""
        if not self.map_id:
            self.map_id = self.find_map("ingress_map")
            if not self.map_id:
                return False
        
        console.print(f"\n[blue]Removing IP from ingress_map: {ip_addr}[/blue]")
        
        try:
            # Convert IP to LPM trie key format
            ip_bytes = socket.inet_aton(ip_addr)
            prefix_len = 32
            
            # Key format: [prefix_len: 4 bytes] [ip: 4 bytes]
            key_hex = []
            key_hex.extend([f'{(prefix_len >> (8*i)) & 0xff:02x}' for i in range(4)])
            key_hex.extend([f'{b:02x}' for b in ip_bytes])
            
            cmd = [
                "bpftool", "map", "delete",
                "id", str(self.map_id),
                "key", "hex"] + key_hex
            
            self._run(cmd)
            console.print(f"[green][OK] IP {ip_addr}/32 removed from ingress_map[/green]")
            return True
            
        except Exception as e:
            console.print(f"[red][ERROR] Failed to remove IP: {e}[/red]")
            return False
    
    def dump_map(self) -> str:
        """Get contents of all relevant BPF maps with decoded values.
        
        Returns:
            String containing map contents with human-readable interpretation
        """
        output = []
        
        # 1. Dump ingress_map (allowed IPs)
        output.append("[bold cyan]═══ ingress_map (Allowed IPs) ═══[/bold cyan]")
        if not self.map_id:
            self.map_id = self.find_map("ingress_map")
        
        if self.map_id:
            try:
                result = self._run(["bpftool", "map", "dump", "id", str(self.map_id)])
                if result.stdout.strip():
                    lines = result.stdout.strip().split('\n')
                    key_count = 0
                    i = 0
                    while i < len(lines):
                        line = lines[i].strip()
                        if line.startswith('key:'):
                            # Next line has the key bytes
                            if i + 1 < len(lines):
                                key_line = lines[i + 1].strip()
                                parts = key_line.split()
                                if len(parts) >= 8:
                                    # First 4 bytes are prefix length (little-endian)
                                    prefix_len = int(parts[0], 16)
                                    # Next 4 bytes are the IP (little-endian)
                                    ip = f"{int(parts[4], 16)}.{int(parts[5], 16)}.{int(parts[6], 16)}.{int(parts[7], 16)}"
                                    key_count += 1
                                    output.append(f"  [green]✓ Allowed: {ip}/{prefix_len}[/green]")
                                i += 1
                            # Skip the value lines (they're port/protocol rules - just skip for now)
                            while i + 1 < len(lines) and not lines[i + 1].strip().startswith('key:'):
                                i += 1
                        i += 1
                    
                    if key_count == 0:
                        output.append("  [dim](empty - no IPs allowed)[/dim]")
                else:
                    output.append("  [dim](empty - no IPs allowed)[/dim]")
            except Exception as e:
                output.append(f"  [red]Error: {e}[/red]")
        else:
            output.append("  [red]Map not found[/red]")
        
        output.append("")
        
        # 2. Dump ingress_pod_state_map
        output.append("[bold cyan]═══ ingress_pod_state_map (Pod State) ═══[/bold cyan]")
        
        # Try pinned path first, then search by name
        try:
            result = self._run(["bpftool", "map", "dump", "pinned", "/sys/fs/bpf/tc/globals/ingress_pod_state_map"], check=False)
            if result.returncode != 0 or not result.stdout.strip():
                # Fall back to finding by ID
                pod_state_map_id = self.find_map("ingress_pod_sta")  # Use truncated name
                if not pod_state_map_id:
                    output.append("  [dim]Map not found (programs not loaded yet)[/dim]")
                    output.append("")
                else:
                    result = self._run(["bpftool", "map", "dump", "id", str(pod_state_map_id)])
            
            if result.stdout.strip():
                lines = result.stdout.strip().split('\n')
                found_entries = False
                
                # Simple parsing: key: XX XX XX XX  value: YY
                for line in lines:
                    if line.startswith('key:') and 'value:' in line:
                        # Format: "key: 00 00 00 00  value: 00"
                        parts = line.split('value:')
                        if len(parts) == 2:
                            key_part = parts[0].replace('key:', '').strip().split()
                            value_part = parts[1].strip().split()
                            
                            if key_part and value_part:
                                try:
                                    key_val = int(key_part[0], 16)
                                    state_byte = int(value_part[0], 16)
                                    
                                    state_map = {0: 'POLICIES_APPLIED (deny-by-default)', 
                                               1: 'DEFAULT_ALLOW (permit all)', 
                                               2: 'DEFAULT_DENY'}
                                    state_name = state_map.get(state_byte, f"UNKNOWN ({state_byte})")
                                    
                                    key_name = "Namespace Policy" if key_val == 0 else "Cluster Policy"
                                    output.append(f"  {key_name}: [yellow]{state_name}[/yellow]")
                                    found_entries = True
                                except (ValueError, IndexError):
                                    pass
                
                if not found_entries:
                    output.append("  [dim](no entries found)[/dim]")
            else:
                output.append("  [dim](empty)[/dim]")
                
        except Exception as e:
            output.append(f"  [red]Error: {e}[/red]")
        
        output.append("")
        
        # 3. Dump aws_conntrack_map (connection tracking)
        output.append("[bold cyan]═══ aws_conntrack_map (Active Flows) ═══[/bold cyan]")
        conntrack_map_id = self.find_map("aws_conntrack_map")
        if conntrack_map_id:
            try:
                result = self._run(["bpftool", "map", "dump", "id", str(conntrack_map_id)])
                if result.stdout.strip():
                    lines = result.stdout.strip().split('\n')
                    flow_count = 0
                    i = 0
                    
                    while i < len(lines):
                        line = lines[i].strip()
                        if line.startswith('key:'):
                            # Next line(s) contain the key
                            if i + 1 < len(lines):
                                # Key format: src_ip(4) src_port(2) padding(2) dest_ip(4) dest_port(2) proto(1) padding(1) owner_ip(4)
                                key_line = lines[i + 1].strip()
                                parts = key_line.split()
                                
                                try:
                                    # src_ip (bytes 0-3, little-endian)
                                    src_ip = f"{int(parts[0], 16)}.{int(parts[1], 16)}.{int(parts[2], 16)}.{int(parts[3], 16)}"
                                    
                                    # src_port (bytes 4-5, little-endian)
                                    src_port = int(parts[4], 16) + (int(parts[5], 16) << 8)
                                    
                                    # dest_ip (bytes 8-11, little-endian)
                                    dst_ip = f"{int(parts[8], 16)}.{int(parts[9], 16)}.{int(parts[10], 16)}.{int(parts[11], 16)}"
                                    
                                    # dest_port (bytes 12-13, little-endian)
                                    dst_port = int(parts[12], 16) + (int(parts[13], 16) << 8)
                                    
                                    # protocol (byte 14)
                                    proto = int(parts[14], 16)
                                    proto_name = {6: 'TCP', 17: 'UDP', 132: 'SCTP'}.get(proto, str(proto))
                                    
                                    flow_count += 1
                                    output.append(f"  [cyan]Flow #{flow_count}:[/cyan] {src_ip}:{src_port} → {dst_ip}:{dst_port} ({proto_name})")
                                    
                                    # Find and parse value (just show it exists)
                                    i += 1
                                    while i < len(lines) and not lines[i].strip().startswith('value:'):
                                        # Handle multi-line keys
                                        if i + 1 < len(lines) and not lines[i + 1].strip().startswith('value:') and not lines[i + 1].strip().startswith('key:'):
                                            i += 1
                                        else:
                                            break
                                    
                                    if i < len(lines) and lines[i].strip().startswith('value:'):
                                        i += 1
                                        if i < len(lines):
                                            value_line = lines[i].strip()
                                            value_parts = value_line.split()
                                            if value_parts:
                                                ct_val = int(value_parts[0], 16)
                                                output.append(f"    [dim]State: {ct_val}[/dim]")
                                except Exception as parse_err:
                                    output.append(f"    [dim]Parse error: {parse_err}[/dim]")
                        i += 1
                    
                    if flow_count == 0:
                        output.append("  [dim](no active flows)[/dim]")
                else:
                    output.append("  [dim](no active flows)[/dim]")
            except Exception as e:
                output.append(f"  [red]Error: {e}[/red]")
        else:
            output.append("  [red]Map not found[/red]")
        
        return '\n'.join(output)
    
    def load_and_attach(self, obj_file: Optional[Path] = None) -> bool:
        """Complete program loading workflow.
        
        Args:
            obj_file: Optional object file path. If not provided, uses self.obj_file
        """
        if obj_file:
            self.obj_file = obj_file
        
        if not self.obj_file or not self.obj_file.exists():
            console.print(f"[red][ERROR] Object file not found: {self.obj_file}[/red]")
            console.print("[yellow][WARN] Compile the program first[/yellow]")
            return False
        
        if not self.setup_qdisc():
            return False
        
        self.cleanup_filters()
        
        # Clean up pinned maps to ensure fresh state
        self.cleanup_pinned_maps()
        
        # Load ingress program (K8s Ingress policy - checks SOURCE IP)
        console.print("\n[blue]Loading ingress program...[/blue]")
        if not self.load_program():
            return False
        
        if not self.verify_program():
            return False
        
        # Load egress program if available (K8s Egress policy - checks DESTINATION IP)
        if self.egress_obj_file and self.egress_obj_file.exists():
            console.print("\n[blue]Loading egress program...[/blue]")
            # Temporarily switch to egress program
            original_obj = self.obj_file
            self.obj_file = self.egress_obj_file
            
            if not self.load_program():
                console.print("[yellow][WARN] Egress program failed to load, continuing with ingress only[/yellow]")
                self.obj_file = original_obj  # Restore
            else:
                # Verify egress program
                if self.verify_program():
                    console.print("[green][OK] Egress program loaded successfully[/green]")
                else:
                    console.print("[yellow][WARN] Egress program verification failed[/yellow]")
                self.obj_file = original_obj  # Restore
        
        # Find the ingress map
        self.find_map("ingress_map")
        
        # Initialize pod state maps (required for AWS VPC CNI)
        self.initialize_pod_state_maps()
        
        console.print("\n[green bold][OK] BPF program(s) active[/green bold]")
        return True
    
    def full_setup(self) -> bool:
        """Complete setup: compile, load, and attach BPF program.
        
        Returns:
            bool: True if all steps successful
        """
        console.print("[bold cyan]═══ BPF Full Setup ═══[/bold cyan]")
        
        # Step 1: Compile
        console.print("\n[bold]1. Compiling BPF program...[/bold]")
        if not self.compile():
            console.print("\n[red]Setup failed at compilation step[/red]")
            self.get_status_report()
            return False
        
        # Step 2: Load and attach
        console.print("\n[bold]2. Loading and attaching...[/bold]")
        if not self.load_and_attach():
            console.print("\n[red]Setup failed at load/attach step[/red]")
            self.get_status_report()
            return False
        
        console.print("\n[bold green][OK] BPF setup complete![/bold green]")
        
        # Show comprehensive status report
        self.get_status_report()
        
        return True
    
    def get_status_report(self, print_output: bool = True) -> dict:
        """Generate comprehensive status report of all setup steps.
        
        Args:
            print_output: If True, prints formatted table to console. If False, only returns data.
        
        Returns:
            dict: Status report with step results
        """
        from rich.table import Table
        
        if print_output:
            console.print("\n[bold cyan]═══ System Status Report ═══[/bold cyan]")
        
        report = {
            "steps": [],
            "overall_status": "PASS"
        }
        
        # Step 1: Network Setup
        step1 = {"id": 1, "name": "Network Setup", "status": "PASS", "details": []}
        try:
            # Check namespaces
            result = self._run(["ip", "netns", "list"], check=False)
            namespaces = ["ns-backend", "ns-allowed", "ns-denied"]
            found_ns = []
            for ns in namespaces:
                if ns in result.stdout:
                    found_ns.append(ns)
                    step1["details"].append(f"✓ Namespace {ns} exists")
                else:
                    step1["status"] = "FAIL"
                    step1["details"].append(f"✗ Namespace {ns} missing")
            
            # Check interfaces
            if self.interface:
                result = self._run(["ip", "link", "show", self.interface], check=False)
                if result.returncode == 0:
                    step1["details"].append(f"✓ Interface {self.interface} exists")
                else:
                    step1["status"] = "FAIL"
                    step1["details"].append(f"✗ Interface {self.interface} not found")
        except Exception as e:
            step1["status"] = "FAIL"
            step1["details"].append(f"✗ Error: {str(e)[:50]}")
        
        report["steps"].append(step1)
        
        # Step 2: Compilation
        step2 = {"id": 2, "name": "Program Compilation", "status": "PASS", "details": []}
        try:
            # Look for compiled files even if not in self.obj_file
            c_dir = Path.cwd() / "ebpf" / "c"
            ingress_obj = c_dir / "tc.v4ingress.bpf.o"
            egress_obj = c_dir / "tc.v4egress.bpf.o"
            
            if ingress_obj.exists():
                size = ingress_obj.stat().st_size
                step2["details"].append(f"✓ Ingress program compiled ({size} bytes)")
                # Update self.obj_file for later checks
                if not self.obj_file:
                    self.obj_file = ingress_obj
            elif self.obj_file and self.obj_file.exists():
                size = self.obj_file.stat().st_size
                step2["details"].append(f"✓ Ingress program compiled ({size} bytes)")
            else:
                step2["status"] = "FAIL"
                step2["details"].append(f"✗ Ingress .o file not found")
            
            if egress_obj.exists():
                size = egress_obj.stat().st_size
                step2["details"].append(f"✓ Egress program compiled ({size} bytes)")
                # Update self.egress_obj_file for later checks
                if not self.egress_obj_file:
                    self.egress_obj_file = egress_obj
            elif self.egress_obj_file and self.egress_obj_file.exists():
                size = self.egress_obj_file.stat().st_size
                step2["details"].append(f"✓ Egress program compiled ({size} bytes)")
            else:
                step2["status"] = "WARN"
                step2["details"].append(f"⚠ Egress .o file not found (optional)")
        except Exception as e:
            step2["status"] = "FAIL"
            step2["details"].append(f"✗ Error: {str(e)[:50]}")
        
        report["steps"].append(step2)
        
        # Step 3: Qdisc Setup
        step3 = {"id": 3, "name": "TC Qdisc Setup", "status": "PASS", "details": []}
        try:
            result = self._run(["tc", "qdisc", "show", "dev", self.interface], check=False)
            if "clsact" in result.stdout:
                step3["details"].append(f"✓ clsact qdisc attached to {self.interface}")
            else:
                step3["status"] = "FAIL"
                step3["details"].append(f"✗ clsact qdisc not found on {self.interface}")
        except Exception as e:
            step3["status"] = "FAIL"
            step3["details"].append(f"✗ Error: {str(e)[:50]}")
        
        report["steps"].append(step3)
        
        # Step 4: Program Load
        step4 = {"id": 4, "name": "BPF Program Load", "status": "PASS", "details": []}
        try:
            # Check ingress program (attaches to TC egress because it checks packets going TO pod)
            direction = "egress" if self.obj_file and "ingress" in str(self.obj_file) else "ingress"
            result = self._run(["tc", "filter", "show", "dev", self.interface, direction], check=False)
            if "bpf" in result.stdout and "tc_cls" in result.stdout:
                step4["details"].append(f"✓ Ingress program attached (TC {direction})")
                # Extract program ID
                for line in result.stdout.split('\n'):
                    if 'id' in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == 'id' and i + 1 < len(parts):
                                prog_id = parts[i + 1]
                                step4["details"].append(f"  Program ID: {prog_id}")
                                break
            else:
                step4["status"] = "FAIL"
                step4["details"].append(f"✗ Ingress program not attached to TC {direction}")
            
            # Check egress program if it exists (attaches to TC ingress because it checks packets FROM pod)
            if self.egress_obj_file and self.egress_obj_file.exists():
                egress_direction = "ingress" if "egress" in str(self.egress_obj_file) else "egress"
                result = self._run(["tc", "filter", "show", "dev", self.interface, egress_direction], check=False)
                if "bpf" in result.stdout:
                    step4["details"].append(f"✓ Egress program attached (TC {egress_direction})")
                    # Extract egress program ID
                    for line in result.stdout.split('\n'):
                        if 'id' in line:
                            parts = line.split()
                            for i, part in enumerate(parts):
                                if part == 'id' and i + 1 < len(parts):
                                    egress_prog_id = parts[i + 1]
                                    step4["details"].append(f"  Program ID: {egress_prog_id}")
                                    break
                else:
                    step4["status"] = "WARN"
                    step4["details"].append(f"⚠ Egress program not attached")
        except Exception as e:
            step4["status"] = "FAIL"
            step4["details"].append(f"✗ Error: {str(e)[:50]}")
        
        report["steps"].append(step4)
        
        # Step 5: Map Configuration
        step5 = {"id": 5, "name": "BPF Map Configuration", "status": "PASS", "details": []}
        try:
            # Check ingress_map
            ingress_map_id = self.find_map("ingress_map") if not self.map_id else self.map_id
            if ingress_map_id:
                step5["details"].append(f"✓ ingress_map found (ID: {ingress_map_id})")
                # Count entries
                result = self._run(["bpftool", "map", "dump", "id", str(ingress_map_id)], check=False)
                entry_count = result.stdout.count("key:")
                step5["details"].append(f"  Allowed IPs: {entry_count}")
            else:
                step5["status"] = "FAIL"
                step5["details"].append(f"✗ ingress_map not found")
            
            # Check pod state map
            pod_state_id = self.find_map("ingress_pod_state_map")
            if pod_state_id:
                step5["details"].append(f"✓ ingress_pod_state_map found (ID: {pod_state_id})")
                # Check state values
                result = self._run(["bpftool", "map", "dump", "id", str(pod_state_id)], check=False)
                if "00 00 00 00" in result.stdout:
                    step5["details"].append(f"  Policy mode: POLICIES_APPLIED (deny-by-default)")
                elif "01 00 00 00" in result.stdout:
                    step5["status"] = "WARN"
                    step5["details"].append(f"  ⚠ Policy mode: DEFAULT_ALLOW (permit-all)")
            else:
                step5["status"] = "WARN"
                step5["details"].append(f"⚠ ingress_pod_state_map not found")
            
            # Check conntrack map
            conntrack_id = self.find_map("aws_conntrack_map")
            if conntrack_id:
                step5["details"].append(f"✓ aws_conntrack_map found (ID: {conntrack_id})")
            else:
                step5["status"] = "WARN"
                step5["details"].append(f"⚠ aws_conntrack_map not found")
        except Exception as e:
            step5["status"] = "FAIL"
            step5["details"].append(f"✗ Error: {str(e)[:50]}")
        
        report["steps"].append(step5)
        
        # Step 6: Connectivity Test
        step6 = {"id": 6, "name": "Connectivity Test", "status": "PASS", "details": []}
        try:
            # Test allowed client
            result = self._run([
                "ip", "netns", "exec", "ns-allowed",
                "timeout", "2", "nc", "-zv", "10.0.0.10", "8080"
            ], check=False)
            
            if result.returncode == 0:
                step6["details"].append(f"✓ Allowed client (10.0.0.20) can connect")
            elif result.returncode == 124:
                step6["status"] = "FAIL"
                step6["details"].append(f"✗ Allowed client (10.0.0.20) BLOCKED (timeout)")
            elif result.returncode == 1 and "refused" in result.stderr:
                step6["status"] = "WARN"
                step6["details"].append(f"⚠ Backend server not running (connection refused)")
            else:
                step6["status"] = "FAIL"
                step6["details"].append(f"✗ Allowed client test failed (exit {result.returncode})")
            
            # Test denied client
            result = self._run([
                "ip", "netns", "exec", "ns-denied",
                "timeout", "2", "nc", "-zv", "10.0.0.10", "8080"
            ], check=False)
            
            if result.returncode == 124:
                step6["details"].append(f"✓ Denied client (10.0.0.30) BLOCKED (timeout)")
            elif result.returncode == 0:
                step6["status"] = "FAIL"
                step6["details"].append(f"✗ Denied client (10.0.0.30) can connect (policy FAIL)")
            elif result.returncode == 1 and "refused" in result.stderr:
                step6["status"] = "WARN"
                step6["details"].append(f"⚠ Backend server not running")
            else:
                step6["status"] = "WARN"
                step6["details"].append(f"⚠ Denied client test inconclusive (exit {result.returncode})")
        except Exception as e:
            step6["status"] = "FAIL"
            step6["details"].append(f"✗ Error: {str(e)[:50]}")
        
        report["steps"].append(step6)
        
        # Determine overall status
        for step in report["steps"]:
            if step["status"] == "FAIL":
                report["overall_status"] = "FAIL"
            elif step["status"] == "WARN" and report["overall_status"] != "FAIL":
                report["overall_status"] = "WARN"
        
        # Print formatted output if requested
        if print_output:
            # Create summary table
            table = Table(title="Setup Status Report", show_header=True, header_style="bold magenta")
            table.add_column("Step", style="cyan", width=3)
            table.add_column("Name", style="cyan", width=22)
            table.add_column("Status", width=8)
            table.add_column("Details", width=60)
            
            for step in report["steps"]:
                status_style = {
                    "PASS": "[green]✅ PASS[/green]",
                    "FAIL": "[red]❌ FAIL[/red]",
                    "WARN": "[yellow]⚠️  WARN[/yellow]"
                }[step["status"]]
                
                details = "\n".join(step["details"])
                table.add_row(str(step["id"]), step["name"], status_style, details)
            
            console.print(table)
            
            # Overall status
            if report["overall_status"] == "PASS":
                console.print("\n[bold green]✅ Overall Status: PASS[/bold green]")
            elif report["overall_status"] == "WARN":
                console.print("\n[bold yellow]⚠️  Overall Status: PASS with warnings[/bold yellow]")
            else:
                console.print("\n[bold red]❌ Overall Status: FAIL[/bold red]")
        
        return report
