"""System status report generation."""

import subprocess
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table

console = Console()


class StatusReporter:
    """Generates comprehensive status reports for the eBPF network policy system."""
    
    def __init__(self, env_mgr, interface: str):
        """Initialize status reporter.
        
        Args:
            env_mgr: EnvironmentManager instance
            interface: Network interface being monitored
        """
        self.env_mgr = env_mgr
        self.interface = interface
    
    def _run(self, cmd: list[str], check: bool = False) -> subprocess.CompletedProcess:
        """Run a command and return result."""
        return subprocess.run(cmd, capture_output=True, text=True)
    
    def _find_map(self, map_name: str) -> Optional[int]:
        """Find BPF map ID by name (handles truncated names)."""
        # Try pinned path first (most reliable)
        pinned_path = f"/sys/fs/bpf/tc/globals/{map_name}"
        result = self._run(["bpftool", "map", "show", "pinned", pinned_path])
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                parts = line.split()
                if parts and parts[0].endswith(':'):
                    try:
                        return int(parts[0].rstrip(':'))
                    except ValueError:
                        pass
        
        # Fall back to searching by truncated name (BPF_OBJ_NAME_LEN = 16, including null terminator)
        # "ingress_pod_state_map" becomes "ingress_pod_sta"
        # "aws_conntrack_map" becomes "aws_conntrack_m"
        truncated_name = map_name[:15]
        result = self._run(["bpftool", "map", "list"])
        for line in result.stdout.split('\n'):
            if truncated_name in line or map_name in line:
                parts = line.split()
                if parts and parts[0].endswith(':'):
                    try:
                        return int(parts[0].rstrip(':'))
                    except ValueError:
                        pass
        return None
    
    def generate_report(self, print_output: bool = True) -> dict:
        """Generate comprehensive status report of all setup steps.
        
        Args:
            print_output: If True, prints formatted table to console. If False, only returns data.
        
        Returns:
            dict: Status report with step results
        """
        if print_output:
            console.print("\n[bold cyan]═══ System Status Report ═══[/bold cyan]")
        
        report = {
            "steps": [],
            "overall_status": "PASS"
        }
        
        # Step 0: Environment Check
        step0 = self._check_environment()
        report["steps"].append(step0)
        
        # Step 1: Network Setup
        step1 = self._check_network()
        report["steps"].append(step1)
        
        # Step 2: Compilation
        step2 = self._check_compilation()
        report["steps"].append(step2)
        
        # Step 3: Qdisc Setup
        step3 = self._check_qdisc()
        report["steps"].append(step3)
        
        # Step 4: Program Load
        step4 = self._check_program_load()
        report["steps"].append(step4)
        
        # Step 5: Map Configuration
        step5 = self._check_maps()
        report["steps"].append(step5)
        
        # Step 6: Connectivity Test
        step6 = self._check_connectivity()
        report["steps"].append(step6)
        
        # Determine overall status
        for step in report["steps"]:
            if step["status"] == "FAIL":
                report["overall_status"] = "FAIL"
            elif step["status"] == "WARN" and report["overall_status"] != "FAIL":
                report["overall_status"] = "WARN"
        
        # Print formatted output if requested
        if print_output:
            self._print_report(report)
        
        return report
    
    def _check_environment(self) -> dict:
        """Check environment requirements."""
        step = {"id": 0, "name": "Environment Check", "status": "PASS", "details": []}
        try:
            # Check root
            if self.env_mgr.check_root():
                step["details"].append("✓ Running as root")
            else:
                step["status"] = "FAIL"
                step["details"].append("✗ Not running as root")
            
            # Check required tools
            present, missing = self.env_mgr.check_dependencies()
            for tool in present:
                step["details"].append(f"✓ {tool} available")
            
            if missing:
                step["status"] = "FAIL"
                for tool in missing:
                    step["details"].append(f"✗ {tool} missing")
            
            # Check ASM headers
            asm_path = Path("/usr/include/asm")
            if asm_path.exists():
                step["details"].append("✓ ASM headers configured")
            else:
                step["status"] = "WARN"
                step["details"].append("⚠ ASM symlink not configured")
        except Exception as e:
            step["status"] = "FAIL"
            step["details"].append(f"✗ Error: {str(e)[:50]}")
        
        return step
    
    def _check_network(self) -> dict:
        """Check network namespace setup."""
        step = {"id": 1, "name": "Network Setup", "status": "PASS", "details": []}
        try:
            # Check namespaces
            result = self._run(["ip", "netns", "list"])
            namespaces = ["ns-backend", "ns-allowed", "ns-denied"]
            for ns in namespaces:
                if ns in result.stdout:
                    step["details"].append(f"✓ Namespace {ns} exists")
                else:
                    step["status"] = "FAIL"
                    step["details"].append(f"✗ Namespace {ns} missing")
            
            # Check interface
            if self.interface:
                result = self._run(["ip", "link", "show", self.interface])
                if result.returncode == 0:
                    step["details"].append(f"✓ Interface {self.interface} exists")
                else:
                    step["status"] = "FAIL"
                    step["details"].append(f"✗ Interface {self.interface} not found")
        except Exception as e:
            step["status"] = "FAIL"
            step["details"].append(f"✗ Error: {str(e)[:50]}")
        
        return step
    
    def _check_compilation(self) -> dict:
        """Check BPF program compilation."""
        step = {"id": 2, "name": "Program Compilation", "status": "PASS", "details": []}
        try:
            c_dir = Path.cwd() / "ebpf" / "c"
            ingress_obj = c_dir / "tc.v4ingress.bpf.o"
            egress_obj = c_dir / "tc.v4egress.bpf.o"
            
            if ingress_obj.exists():
                size = ingress_obj.stat().st_size
                step["details"].append(f"✓ Ingress program compiled ({size} bytes)")
            else:
                step["status"] = "FAIL"
                step["details"].append(f"✗ Ingress .o file not found")
            
            if egress_obj.exists():
                size = egress_obj.stat().st_size
                step["details"].append(f"✓ Egress program compiled ({size} bytes)")
            else:
                step["status"] = "WARN"
                step["details"].append(f"⚠ Egress .o file not found (optional)")
        except Exception as e:
            step["status"] = "FAIL"
            step["details"].append(f"✗ Error: {str(e)[:50]}")
        
        return step
    
    def _check_qdisc(self) -> dict:
        """Check TC qdisc setup."""
        step = {"id": 3, "name": "TC Qdisc Setup", "status": "PASS", "details": []}
        try:
            result = self._run(["tc", "qdisc", "show", "dev", self.interface])
            if "clsact" in result.stdout:
                step["details"].append(f"✓ clsact qdisc attached to {self.interface}")
            else:
                step["status"] = "FAIL"
                step["details"].append(f"✗ clsact qdisc not found on {self.interface}")
        except Exception as e:
            step["status"] = "FAIL"
            step["details"].append(f"✗ Error: {str(e)[:50]}")
        
        return step
    
    def _check_program_load(self) -> dict:
        """Check BPF program loading."""
        step = {"id": 4, "name": "BPF Program Load", "status": "PASS", "details": []}
        try:
            # Check ingress program (TC egress)
            result = self._run(["tc", "filter", "show", "dev", self.interface, "egress"])
            if "bpf" in result.stdout and "tc_cls" in result.stdout:
                step["details"].append(f"✓ Ingress program attached (TC egress)")
                for line in result.stdout.split('\n'):
                    if 'id' in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == 'id' and i + 1 < len(parts):
                                prog_id = parts[i + 1]
                                step["details"].append(f"  Program ID: {prog_id}")
                                break
                        break
            else:
                step["status"] = "FAIL"
                step["details"].append(f"✗ Ingress program not attached")
            
            # Check egress program (TC ingress)
            result = self._run(["tc", "filter", "show", "dev", self.interface, "ingress"])
            if "bpf" in result.stdout:
                step["details"].append(f"✓ Egress program attached (TC ingress)")
                for line in result.stdout.split('\n'):
                    if 'id' in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == 'id' and i + 1 < len(parts):
                                prog_id = parts[i + 1]
                                step["details"].append(f"  Program ID: {prog_id}")
                                break
                        break
            else:
                step["status"] = "WARN"
                step["details"].append(f"⚠ Egress program not attached")
        except Exception as e:
            step["status"] = "FAIL"
            step["details"].append(f"✗ Error: {str(e)[:50]}")
        
        return step
    
    def _check_maps(self) -> dict:
        """Check BPF map configuration."""
        step = {"id": 5, "name": "BPF Map Configuration", "status": "PASS", "details": []}
        try:
            # Check ingress_map
            ingress_map_id = self._find_map("ingress_map")
            if ingress_map_id:
                step["details"].append(f"✓ ingress_map found (ID: {ingress_map_id})")
                result = self._run(["bpftool", "map", "dump", "id", str(ingress_map_id)])
                entry_count = result.stdout.count("key:")
                step["details"].append(f"  Allowed IPs: {entry_count}")
            else:
                step["status"] = "FAIL"
                step["details"].append(f"✗ ingress_map not found")
            
            # Check pod state map (uses pinned path due to name truncation)
            pod_state_id = self._find_map("ingress_pod_state_map")
            if pod_state_id:
                step["details"].append(f"✓ ingress_pod_state_map found (ID: {pod_state_id})")
                # Use pinned path for reliable access
                result = self._run(["bpftool", "map", "dump", "pinned", "/sys/fs/bpf/tc/globals/ingress_pod_state_map"])
                if result.returncode == 0:
                    if "00 00 00 00" in result.stdout:
                        step["details"].append(f"  Policy mode: POLICIES_APPLIED (deny-by-default)")
                    elif "01 00 00 00" in result.stdout:
                        step["status"] = "WARN"
                        step["details"].append(f"  ⚠ Policy mode: DEFAULT_ALLOW (permit-all)")
            else:
                step["status"] = "WARN"
                step["details"].append(f"⚠ ingress_pod_state_map not found")
            
            # Check conntrack map (uses pinned path due to name truncation)
            conntrack_id = self._find_map("aws_conntrack_map")
            if conntrack_id:
                step["details"].append(f"✓ aws_conntrack_map found (ID: {conntrack_id})")
            else:
                step["status"] = "WARN"
                step["details"].append(f"⚠ aws_conntrack_map not found")
        except Exception as e:
            step["status"] = "FAIL"
            step["details"].append(f"✗ Error: {str(e)[:50]}")
        
        return step
    
    def _check_connectivity(self) -> dict:
        """Check network connectivity tests."""
        step = {"id": 6, "name": "Connectivity Test", "status": "PASS", "details": []}
        try:
            # Test allowed client
            result = self._run([
                "ip", "netns", "exec", "ns-allowed",
                "timeout", "2", "nc", "-zv", "10.0.0.10", "8080"
            ])
            
            if result.returncode == 0:
                step["details"].append(f"✓ Allowed client (10.0.0.20) can connect")
            elif result.returncode == 124:
                step["status"] = "FAIL"
                step["details"].append(f"✗ Allowed client (10.0.0.20) BLOCKED (timeout)")
            elif result.returncode == 1 and "refused" in result.stderr:
                step["status"] = "WARN"
                step["details"].append(f"⚠ Backend server not running (connection refused)")
            else:
                step["status"] = "FAIL"
                step["details"].append(f"✗ Allowed client test failed (exit {result.returncode})")
            
            # Test denied client
            result = self._run([
                "ip", "netns", "exec", "ns-denied",
                "timeout", "2", "nc", "-zv", "10.0.0.10", "8080"
            ])
            
            if result.returncode == 124:
                step["details"].append(f"✓ Denied client (10.0.0.30) BLOCKED (timeout)")
            elif result.returncode == 0:
                step["status"] = "FAIL"
                step["details"].append(f"✗ Denied client (10.0.0.30) can connect (policy FAIL)")
            elif result.returncode == 1 and "refused" in result.stderr:
                step["status"] = "WARN"
                step["details"].append(f"⚠ Backend server not running")
            else:
                step["status"] = "WARN"
                step["details"].append(f"⚠ Denied client test inconclusive (exit {result.returncode})")
        except Exception as e:
            step["status"] = "FAIL"
            step["details"].append(f"✗ Error: {str(e)[:50]}")
        
        return step
    
    def _print_report(self, report: dict) -> None:
        """Print formatted status report."""
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
