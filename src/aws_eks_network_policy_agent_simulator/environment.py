"""Environment setup and dependency management."""

import os
import subprocess
import shutil
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.panel import Panel

console = Console()


class EnvironmentManager:
    """Manages system dependencies and environment setup."""
    
    REQUIRED_PACKAGES = [
        "clang",
        "llvm", 
        "libbpf-dev",
        "iproute2",
        "bpftool"
    ]
    
    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or Path.cwd()
        self.kernel_headers = f"linux-headers-{os.uname().release}"
        
    def check_root(self) -> bool:
        """Check if running as root."""
        return os.geteuid() == 0
    
    def check_command(self, cmd: str) -> bool:
        """Check if a command is available."""
        return shutil.which(cmd) is not None
    
    def check_dependencies(self) -> tuple[list[str], list[str]]:
        """Check which dependencies are present and which are missing."""
        present = []
        missing = []
        
        for cmd in ["clang", "bpftool", "tc", "ip"]:
            if self.check_command(cmd):
                present.append(cmd)
            else:
                missing.append(cmd)
        
        return present, missing
    
    def install_dependencies(self) -> bool:
        """Install required system dependencies."""
        console.print("[yellow]Installing eBPF toolchain dependencies...[/yellow]")
        
        packages = self.REQUIRED_PACKAGES + [self.kernel_headers]
        
        try:
            cmd = ["apt", "install", "-y"] + packages
            console.print(f"[dim]Running: {' '.join(cmd)}[/dim]")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                console.print("[green][OK] All dependencies installed[/green]")
                return True
            else:
                console.print(f"[red][ERROR] Installation failed: {result.stderr}[/red]")
                return False
                
        except Exception as e:
            console.print(f"[red][ERROR] Error installing dependencies: {e}[/red]")
            return False
    
    def setup_asm_symlink(self) -> bool:
        """Create /usr/include/asm symlink if needed."""
        asm_path = Path("/usr/include/asm")
        
        if asm_path.exists():
            target = asm_path.resolve()
            console.print(f"[green][OK] ASM symlink exists -> {target}[/green]")
            return True
        
        # Determine architecture
        arch = os.uname().machine
        arch_map = {
            "x86_64": "x86_64-linux-gnu",
            "aarch64": "aarch64-linux-gnu",
            "arm64": "aarch64-linux-gnu"
        }
        
        arch_dir = arch_map.get(arch, f"{arch}-linux-gnu")
        source = Path(f"/usr/include/{arch_dir}/asm")
        
        if not source.exists():
            console.print(f"[red][ERROR] Architecture headers not found at {source}[/red]")
            return False
        
        try:
            console.print(f"[yellow]Creating symlink: {asm_path} -> {source}[/yellow]")
            os.symlink(source, asm_path)
            console.print("[green][OK] ASM symlink created[/green]")
            return True
        except Exception as e:
            console.print(f"[red][ERROR] Failed to create symlink: {e}[/red]")
            return False
    
    def compile_bpf_program(self, source_file: Path) -> Optional[Path]:
        """Compile C source to BPF bytecode."""
        if not source_file.exists():
            console.print(f"[red][ERROR] Source file not found: {source_file}[/red]")
            return None
        
        output_file = source_file.with_suffix('.o')
        
        console.print(f"\n[blue]Compiling BPF program...[/blue]")
        console.print(f"[dim]Source: {source_file}[/dim]")
        console.print(f"[dim]Output: {output_file}[/dim]")
        
        cmd = [
            "clang",
            "-O2",
            "-g", 
            "-target", "bpf",
            "-c", str(source_file),
            "-o", str(output_file)
        ]
        
        console.print(f"[dim]Command: {' '.join(cmd)}[/dim]")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=source_file.parent
            )
            
            if result.returncode == 0:
                size = output_file.stat().st_size
                console.print(f"[green][OK] Compilation successful ({size} bytes)[/green]")
                return output_file
            else:
                console.print("[red][ERROR] Compilation failed:[/red]")
                console.print(result.stderr)
                return None
                
        except Exception as e:
            console.print(f"[red][ERROR] Compilation error: {e}[/red]")
            return None
    
    def setup_environment(self) -> bool:
        """Complete environment setup."""
        console.print(Panel.fit(
            "[bold blue]eBPF Environment Setup[/bold blue]",
            border_style="blue"
        ))
        
        # Check root
        if not self.check_root():
            console.print("[red][ERROR] Must run as root (use sudo)[/red]")
            return False
        
        console.print("[green][OK] Running as root[/green]")
        
        # Check dependencies
        present, missing = self.check_dependencies()
        
        if missing:
            console.print(f"[yellow]Missing commands: {', '.join(missing)}[/yellow]")
            if not self.install_dependencies():
                return False
        else:
            console.print(f"[green][OK] All tools present: {', '.join(present)}[/green]")
        
        # Setup ASM symlink
        if not self.setup_asm_symlink():
            return False
        
        console.print("\n[green bold][OK] Environment ready for eBPF development[/green bold]")
        return True
