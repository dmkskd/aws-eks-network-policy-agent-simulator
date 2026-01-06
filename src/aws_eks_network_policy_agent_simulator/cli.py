"""Interactive CLI for eBPF management."""

import sys
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table

from .environment import EnvironmentManager
from .network import NetworkManager
from .bpf import BPFManager

console = Console()


class EBPFCLIManager:
    """Interactive CLI for managing eBPF programs."""
    
    def __init__(self):
        self.base_dir = Path.cwd()
        self.env_mgr = EnvironmentManager(self.base_dir)
        self.net_mgr = NetworkManager()
        # BPF manager now owns source file discovery and compilation
        self.bpf_mgr = BPFManager(self.net_mgr.host_iface)
    
    def show_menu(self) -> str:
        """Display main menu and get user choice."""
        console.print("\n" + "="*60)
        console.print(Panel.fit(
            "[bold cyan]eBPF Network Policy Manager[/bold cyan]",
            border_style="cyan"
        ))
        
        table = Table(show_header=False, box=None)
        table.add_column("Option", style="yellow", width=3)
        table.add_column("Description", style="white")
        
        table.add_row("1", "Setup Environment (install dependencies)")
        table.add_row("2", "Setup Network (create veth pair & namespace)")
        table.add_row("3", "Compile BPF Program")
        table.add_row("4", "Load BPF Program")
        table.add_row("5", "Add Allowed IP")
        table.add_row("6", "Remove Allowed IP")
        table.add_row("7", "Show Allowed IPs")
        table.add_row("8", "Test Ping (from pod to host)")
        table.add_row("9", "Show Network Status")
        table.add_row("s", "Status Report (all 6 steps)")
        table.add_row("0", "Run Full Setup (1→2→3→4)")
        table.add_row("q", "Quit")
        
        console.print(table)
        console.print("="*60)
        
        return Prompt.ask("\n[bold]Choose an option[/bold]", default="0")
    
    def setup_environment(self) -> bool:
        """Setup system environment."""
        return self.env_mgr.setup_environment()
    
    def setup_network(self) -> bool:
        """Setup network interfaces and namespaces."""
        return self.net_mgr.setup_network()
    
    def compile_program(self) -> bool:
        """Compile BPF program - delegates to bpf manager."""
        return self.bpf_mgr.compile()
    
    def load_program(self) -> bool:
        """Load BPF program into kernel - delegates to bpf manager."""
        return self.bpf_mgr.load_and_attach()
    
    def add_ip(self) -> None:
        """Add IP to allowed list."""
        ip = Prompt.ask("[bold]Enter IP address to allow[/bold]", default="10.0.0.2")
        self.bpf_mgr.add_allowed_ip(ip)
        self.bpf_mgr.dump_map()
    
    def remove_ip(self) -> None:
        """Remove IP from allowed list."""
        ip = Prompt.ask("[bold]Enter IP address to remove[/bold]")
        self.bpf_mgr.remove_allowed_ip(ip)
        self.bpf_mgr.dump_map()
    
    def show_allowed_ips(self) -> None:
        """Display allowed IPs."""
        self.bpf_mgr.dump_map()
    
    def test_ping(self) -> None:
        """Test connectivity from pod to host."""
        console.print("\n[blue]Testing ping from pod namespace to host...[/blue]")
        
        import subprocess
        try:
            result = subprocess.run(
                ["ip", "netns", "exec", self.net_mgr.namespace,
                 "ping", "-c", "4", self.net_mgr.host_ip.split('/')[0]],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            console.print(result.stdout)
            
            if result.returncode == 0:
                console.print("[green][OK] Ping successful - packets allowed[/green]")
            else:
                console.print("[red][ERROR] Ping failed - packets dropped by BPF program[/red]")
                console.print("[yellow]Hint: Add pod IP (10.0.0.2) to allowed list[/yellow]")
                
        except subprocess.TimeoutExpired:
            console.print("[red][ERROR] Ping timed out[/red]")
        except Exception as e:
            console.print(f"[red][ERROR] Error: {e}[/red]")
    
    def show_status(self) -> None:
        """Show current network and BPF status."""
        self.net_mgr.show_status()
        
        if self.bpf_mgr.program_id:
            console.print(f"\n[green]BPF Program ID: {self.bpf_mgr.program_id}[/green]")
        
        if self.bpf_mgr.map_id:
            console.print(f"[green]BPF Map ID: {self.bpf_mgr.map_id}[/green]")
            self.bpf_mgr.dump_map()
    
    def run_full_setup(self) -> bool:
        """Run complete setup workflow."""
        console.print(Panel.fit(
            "[bold green]Running Full Setup Workflow[/bold green]",
            border_style="green"
        ))
        
        steps = [
            ("Environment Setup", self.setup_environment),
            ("Network Setup", self.setup_network),
            ("Compile Program", self.compile_program),
            ("Load Program", self.load_program)
        ]
        
        for step_name, step_func in steps:
            console.print(f"\n[bold blue]>>> {step_name}[/bold blue]")
            if not step_func():
                console.print(f"[red][ERROR] {step_name} failed. Aborting.[/red]")
                # Show status report even on failure
                self.bpf_mgr.get_status_report()
                return False
        
        console.print("\n" + "="*60)
        console.print(Panel.fit(
            "[bold green][OK] Full Setup Complete![/bold green]\n\n"
            "Next steps:\n"
            "• Add pod IP to allowed list (option 5)\n"
            "• Test ping connectivity (option 8)\n"
            "• Monitor: sudo cat /sys/kernel/debug/tracing/trace_pipe",
            border_style="green"
        ))
        
        # Show comprehensive status report
        self.bpf_mgr.get_status_report()
        
        # Show ASCII art architecture diagram
        console.print("\n[bold cyan]=== Network Policy Architecture ===[/bold cyan]\n")
        console.print("  [green]┌──────────────┐[/green]                              [yellow]┌──────────────┐[/yellow]")
        console.print("  [green]│   ALLOWED    │[/green]                              [yellow]│   BACKEND    │[/yellow]")
        console.print("  [green]│  10.0.0.20   │[/green]  [green]✓ ALLOW (ingress)[/green]  ──────►  [yellow]│  10.0.0.10   │[/yellow]")
        console.print("  [green]│  (allowed)   │[/green]                              [yellow]│   :8080      │[/yellow]")
        console.print("  [green]└──────────────┘[/green]                              [yellow]└──────────────┘[/yellow]")
        console.print("")
        console.print("  [red]┌──────────────┐[/red]                                    [yellow]▲[/yellow]")
        console.print("  [red]│   DENIED     │[/red]                                    [yellow]│[/yellow]")
        console.print("  [red]│  10.0.0.30   │[/red]  [red]✗ DENY (ingress)[/red]   ──────X    [yellow]│[/yellow]")
        console.print("  [red]│   (denied)   │[/red]                                    [yellow]│[/yellow]")
        console.print("  [red]└──────────────┘[/red]                              [dim]BPF filters[/dim]")
        console.print("")
        
        return True
    
    def run(self) -> None:
        """Main CLI loop."""
        console.print(Panel.fit(
            "[bold cyan]Welcome to eBPF Network Policy Manager[/bold cyan]\n"
            "[dim]Manage eBPF programs and network policies interactively[/dim]",
            border_style="cyan"
        ))
        
        # Check root
        if not self.env_mgr.check_root():
            console.print("[red]Error: Must run as root (use sudo)[/red]")
            sys.exit(1)
        
        while True:
            try:
                choice = self.show_menu()
                
                if choice == 'q':
                    console.print("\n[yellow]Goodbye![/yellow]")
                    break
                elif choice == '0':
                    self.run_full_setup()
                elif choice == '1':
                    self.setup_environment()
                elif choice == '2':
                    self.setup_network()
                elif choice == '3':
                    self.compile_program()
                elif choice == '4':
                    self.load_program()
                elif choice == '5':
                    self.add_ip()
                elif choice == '6':
                    self.remove_ip()
                elif choice == '7':
                    self.show_allowed_ips()
                elif choice == '8':
                    self.test_ping()
                elif choice == '9':
                    self.show_status()
                elif choice == 's':
                    self.bpf_mgr.get_status_report()
                else:
                    console.print("[red]Invalid option[/red]")
                
                if choice != 'q':
                    Prompt.ask("\n[dim]Press Enter to continue[/dim]", default="")
                    
            except KeyboardInterrupt:
                console.print("\n[yellow]Interrupted. Goodbye![/yellow]")
                break
            except Exception as e:
                console.print(f"\n[red]Error: {e}[/red]")
                import traceback
                console.print(f"[dim]{traceback.format_exc()}[/dim]")


def main() -> None:
    """Entry point for the CLI."""
    cli = EBPFCLIManager()
    cli.run()


if __name__ == "__main__":
    main()
