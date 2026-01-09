"""Textual TUI application for eBPF management."""

import asyncio
import subprocess
from pathlib import Path
from typing import Optional

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll, ScrollableContainer
from textual.widgets import Header, Footer, Button, Static, RichLog, Label, Input
from textual.binding import Binding
from textual.reactive import reactive

from .environment import EnvironmentManager
from .network_multi import MultiPodNetworkManager
from .bpf import BPFManager
from .bpfstats import BPFStatsCollector, BPFProgramStats
from .stacks import get_stack_traces_text, start_tc_stack_capture, stop_tc_stack_capture, is_tc_capture_running
from .ringbuf_libbpf import AsyncLibbpfRingBufferConsumer as AsyncRingBufferConsumer, PolicyEvent


class BPFStatsMonitor(Container):
    """Live BPF program performance monitor (bpftop-like).
    
    Displays real-time statistics for loaded eBPF programs:
    - Events per second
    - Average runtime per event
    - Estimated CPU usage
    """
    
    DEFAULT_CSS = """
    BPFStatsMonitor {
        layout: vertical;
        height: auto;
        min-height: 6;
        max-height: 10;
        border: solid $accent;
        padding: 0 1;
        margin: 0 0 1 0;
    }
    
    BPFStatsMonitor .stats-title {
        text-align: center;
        color: $text;
        padding: 0 1;
    }
    
    BPFStatsMonitor .stats-row {
        height: auto;
    }
    
    BPFStatsMonitor .stats-header {
        color: $text-muted;
    }
    
    BPFStatsMonitor .prog-ingress {
        color: $success;
    }
    
    BPFStatsMonitor .prog-egress {
        color: $warning;
    }
    """
    
    # Reactive properties to trigger updates
    ingress_stats: reactive[str] = reactive("[dim]Not loaded[/dim]")
    egress_stats: reactive[str] = reactive("[dim]Not loaded[/dim]")
    monitoring_active: reactive[bool] = reactive(False)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stats_collector = BPFStatsCollector()
        self.ingress_prog_id: Optional[int] = None
        self.egress_prog_id: Optional[int] = None
        self._monitor_task: Optional[asyncio.Task] = None
    
    def compose(self) -> ComposeResult:
        """Compose the stats monitor layout."""
        yield Static("[bold magenta]BPF Performance (bpftop-style)[/bold magenta]", classes="stats-title")
        yield Static("[dim]Program  │ Events/s│   Avg Time│   CPU %[/dim]", classes="stats-header")
        yield Static(id="ingress_stats_line", classes="stats-row prog-ingress")
        yield Static(id="egress_stats_line", classes="stats-row prog-egress")
    
    def watch_ingress_stats(self, new_value: str) -> None:
        """Update ingress stats display."""
        try:
            self.query_one("#ingress_stats_line", Static).update(new_value)
        except Exception:
            pass
    
    def watch_egress_stats(self, new_value: str) -> None:
        """Update egress stats display."""
        try:
            self.query_one("#egress_stats_line", Static).update(new_value)
        except Exception:
            pass
    
    def set_program_ids(self, ingress_id: Optional[int], egress_id: Optional[int]) -> None:
        """Set the program IDs to monitor."""
        self.ingress_prog_id = ingress_id
        self.egress_prog_id = egress_id
    
    async def start_monitoring(self) -> None:
        """Start the stats monitoring loop."""
        if self._monitor_task and not self._monitor_task.done():
            return  # Already running
        
        # Enable kernel BPF stats
        await asyncio.to_thread(self.stats_collector.enable_stats)
        self.monitoring_active = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
    
    async def stop_monitoring(self) -> None:
        """Stop the stats monitoring loop."""
        self.monitoring_active = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
            self._monitor_task = None
        
        # Disable kernel BPF stats to reduce overhead
        await asyncio.to_thread(self.stats_collector.disable_stats)
    
    async def _monitor_loop(self) -> None:
        """Background loop that samples BPF stats every second."""
        try:
            while self.monitoring_active:
                await self._update_stats()
                await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            pass
    
    async def _update_stats(self) -> None:
        """Sample and update stats display."""
        program_ids = []
        if self.ingress_prog_id:
            program_ids.append(self.ingress_prog_id)
        if self.egress_prog_id:
            program_ids.append(self.egress_prog_id)
        
        if not program_ids:
            self.ingress_stats = "[dim]Ingress  │       --│         --│      --[/dim]"
            self.egress_stats = "[dim]Egress   │       --│         --│      --[/dim]"
            return
        
        # Sample stats in background thread
        stats = await asyncio.to_thread(
            self.stats_collector.sample_programs, program_ids
        )
        
        # Format ingress stats
        if self.ingress_prog_id and self.ingress_prog_id in stats:
            s = stats[self.ingress_prog_id]
            self.ingress_stats = self._format_stats_line("Ingress", s, "green")
        else:
            self.ingress_stats = "[dim]Ingress  │       --│         --│      --[/dim]"
        
        # Format egress stats
        if self.egress_prog_id and self.egress_prog_id in stats:
            s = stats[self.egress_prog_id]
            self.egress_stats = self._format_stats_line("Egress", s, "yellow")
        else:
            self.egress_stats = "[dim]Egress   │       --│         --│      --[/dim]"
    
    def _format_stats_line(self, name: str, stats: BPFProgramStats, color: str) -> str:
        """Format a stats line for display."""
        events_sec = stats.events_per_sec
        avg_time_us = stats.avg_runtime_ns / 1000  # Convert to microseconds
        cpu_pct = stats.cpu_percent
        
        # Column widths to match header:
        # "Program  │ Events/s│   Avg Time│   CPU %"
        # COL1=9, COL2=9, COL3=11, COL4=8
        events_str = f"{events_sec:>9.0f}"
        time_str = f"{avg_time_us:>9.2f}µs" if avg_time_us > 0 else "        --"
        cpu_str = f"{cpu_pct:>7.3f}%" if cpu_pct > 0 else "     --"
        
        return f"[{color}]{name:<9}│{events_str}│{time_str}│{cpu_str}[/{color}]"


class StatusBar(Static):
    """Status bar showing current system state."""
    
    program_id: reactive[Optional[int]] = reactive(None)
    map_id: reactive[Optional[int]] = reactive(None)
    network_ready: reactive[bool] = reactive(False)
    
    def render(self) -> str:
        """Render the status bar."""
        parts = []
        
        if self.network_ready:
            parts.append("[green]Network: Ready[/green]")
        else:
            parts.append("[dim]Network: Not configured[/dim]")
        
        if self.program_id:
            parts.append(f"[blue]Program ID: {self.program_id}[/blue]")
        else:
            parts.append("[dim]Program: Not loaded[/dim]")
        
        if self.map_id:
            parts.append(f"[cyan]Map ID: {self.map_id}[/cyan]")
        else:
            parts.append("[dim]Map: N/A[/dim]")
        
        return " | ".join(parts)


class TracePipeLog(Container):
    """Live log viewer for kernel trace output.
    
    Monitors /sys/kernel/debug/tracing/trace_pipe which is the kernel's
    unified tracing interface (ftrace). Shows output from:
    - BPF programs using bpf_trace_printk()
    - Kernel tracepoints
    - kprobes/uprobes
    - Function tracing
    """
    
    DEFAULT_CSS = """
    TracePipeLog {
        layout: vertical;
        height: 100%;
    }
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.trace_task: Optional[asyncio.Task] = None
        self.trace_proc: Optional[subprocess.Popen] = None
        self.event_count = 0
    
    def compose(self) -> ComposeResult:
        """Compose the trace log."""
        yield Static("[bold yellow]═══ Kernel Trace Monitor (/sys/kernel/debug/tracing/trace_pipe) ═══[/bold yellow]", classes="panel-title")
        yield RichLog(id="trace_content", wrap=False, highlight=True, markup=True, max_lines=1000)
    
    def write(self, message: str) -> None:
        """Write a message to the trace log."""
        log = self.query_one("#trace_content", RichLog)
        log.write(message)
    
    def clear(self) -> None:
        """Clear the trace log."""
        log = self.query_one("#trace_content", RichLog)
        log.clear()
    
    async def start_trace(self) -> None:
        """Start reading from trace_pipe."""
        self.clear()
        self.event_count = 0
        
        self.write("[dim]Starting trace_pipe monitor...[/dim]")
        
        # First kill any existing readers
        await asyncio.to_thread(
            subprocess.run,
            ["sudo", "pkill", "-f", "trace_pipe"],
            capture_output=True
        )
        await asyncio.sleep(0.5)
        
        try:
            # Use asyncio.create_subprocess_exec for non-blocking IO
            self.trace_proc = await asyncio.create_subprocess_exec(
                "sudo", "cat", "/sys/kernel/debug/tracing/trace_pipe",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            self.write("[green][OK] Connected to trace_pipe[/green]")
            self.write("[cyan]Listening for BPF events... (send traffic to see output)[/cyan]")
            self.write("[dim]Pod IPs: Backend=10.0.0.10 (0xa00000a), Allowed=10.0.0.20 (0x1400000a), Denied=10.0.0.30 (0x1e00000a)[/dim]")
            self.write("")
            
            # IP decode map (hex to readable)
            ip_map = {
                "0xa00000a": "10.0.0.10 (backend)",
                "0x1400000a": "10.0.0.20 (allowed)",
                "0x1e00000a": "10.0.0.30 (denied)",
            }
            
            # Read lines asynchronously without blocking
            while True:
                try:
                    line = await asyncio.wait_for(
                        self.trace_proc.stdout.readline(),
                        timeout=0.1
                    )
                    if line:
                        decoded = line.decode().rstrip()
                        self.event_count += 1
                        
                        # Decode IPs in the trace
                        display_line = decoded
                        for hex_ip, readable in ip_map.items():
                            if hex_ip in display_line:
                                display_line = display_line.replace(hex_ip, readable)
                        
                        # Highlight based on content
                        if "ALLOW" in display_line and "10.0.0.20" in display_line:
                            # Allowed client - expected to pass
                            self.write(f"[green]✓ {display_line}[/green]")
                        elif "DENY" in display_line and "10.0.0.30" in display_line:
                            # Denied client - expected to be blocked
                            self.write(f"[red]✗ {display_line}[/red]")
                        elif "EGRESS" in display_line or "Egress" in display_line:
                            # Egress program output - show in magenta to distinguish
                            self.write(f"[magenta]{display_line}[/magenta]")
                        elif "ALLOW" in display_line or "DENY" in display_line or "TIER" in display_line:
                            # Other policy decisions
                            self.write(f"[yellow]{display_line}[/yellow]")
                        elif "Packet:" in display_line or "Flow:" in display_line:
                            # Packet/flow info
                            self.write(f"[cyan]{display_line}[/cyan]")
                        else:
                            self.write(f"[dim]{display_line}[/dim]")
                        
                        # Show event count periodically
                        if self.event_count % 50 == 0:
                            self.write(f"[dim]--- {self.event_count} events captured ---[/dim]")
                    else:
                        # EOF reached
                        break
                except asyncio.TimeoutError:
                    # No data, check if process is still running
                    if self.trace_proc.returncode is not None:
                        break
                    continue
                except asyncio.CancelledError:
                    break
            
            try:
                self.write("[dim]Trace monitor stopped[/dim]")
            except Exception:
                pass
                
        except PermissionError:
            try:
                self.write("[red][ERROR] Permission denied[/red]")
                self.write("[yellow]Run as root to access trace_pipe[/yellow]")
            except Exception:
                pass
        except Exception as e:
            try:
                self.write(f"[red][ERROR] Error: {e}[/red]")
            except Exception:
                pass
    
    def stop_trace(self) -> None:
        """Stop reading from trace_pipe."""
        if self.trace_task:
            self.trace_task.cancel()
            self.trace_task = None
        if self.trace_proc:
            try:
                self.trace_proc.terminate()
            except:
                pass
            self.trace_proc = None


class RingBufferLog(Container):
    """Live log viewer for BPF ring buffer events.
    
    Consumes structured events from the policy_events ring buffer using
    the ringbuf_consumer C helper. This provides better formatting than
    trace_pipe since events are structured JSON.
    """
    
    DEFAULT_CSS = """
    RingBufferLog {
        layout: vertical;
        height: 100%;
    }
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.consumer: Optional[AsyncRingBufferConsumer] = None
        self.read_task: Optional[asyncio.Task] = None
        self.event_count = 0
        self.allow_count = 0
        self.deny_count = 0
    
    def compose(self) -> ComposeResult:
        """Compose the ring buffer log."""
        yield Static("[bold cyan]═══ Ring Buffer Events (policy_events) ═══[/bold cyan]", classes="panel-title")
        yield RichLog(id="ringbuf_content", wrap=False, highlight=True, markup=True, max_lines=1000)
    
    def write(self, message: str) -> None:
        """Write a message to the log."""
        try:
            log = self.query_one("#ringbuf_content", RichLog)
            log.write(message)
        except Exception:
            pass
    
    def clear(self) -> None:
        """Clear the log."""
        try:
            log = self.query_one("#ringbuf_content", RichLog)
            log.clear()
        except Exception:
            pass
    
    async def start_consumer(self) -> None:
        """Start consuming ring buffer events."""
        # Stop any existing consumer first (important for re-setup)
        if self.consumer or self.read_task:
            self.write("[dim]Stopping existing consumer...[/dim]")
            await self.stop_consumer()
        
        self.clear()
        self.event_count = 0
        self.allow_count = 0
        self.deny_count = 0
        
        self.consumer = AsyncRingBufferConsumer()
        
        self.write(f"[dim]libbpf available: {self.consumer.consumer_exists}[/dim]")
        self.write(f"[dim]map exists: {self.consumer.map_exists}[/dim]")
        
        if not self.consumer.consumer_exists:
            self.write("[yellow]libbpf not available.[/yellow]")
            self.write("[dim]Make sure libbpf.so.1 is installed.[/dim]")
            return
        
        self.write("[dim]Starting ring buffer consumer (libbpf)...[/dim]")
        
        started = await self.consumer.start()
        self.write(f"[dim]consumer.start() returned: {started}[/dim]")
        
        if not started:
            self.write("[red]Failed to start consumer. Is the BPF program loaded?[/red]")
            return
        
        self.write("[green]Connected to policy_events ring buffer[/green]")
        self.write("[cyan]Listening for policy events... (send traffic to see output)[/cyan]")
        self.write("[dim]Pod IPs: Backend=10.0.0.10, Allowed=10.0.0.20, Denied=10.0.0.30[/dim]")
        self.write("")
        
        # Start reading events
        self.read_task = asyncio.create_task(self._read_loop())
    
    async def _read_loop(self) -> None:
        """Read events from the ring buffer."""
        # Filter to only show events involving our pod IPs
        pod_ips = {"10.0.0.10", "10.0.0.20", "10.0.0.30"}
        
        try:
            async for event in self.consumer.read_events():
                # Filter: only show events where src or dest is one of our pods
                if event.src_ip not in pod_ips and event.dest_ip not in pod_ips:
                    continue
                
                self.event_count += 1
                self._format_event(event)
                
                # Show stats periodically
                if self.event_count % 50 == 0:
                    self.write(f"[dim]--- {self.event_count} events (ALLOW:{self.allow_count} DENY:{self.deny_count}) ---[/dim]")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.write(f"[red]Error reading events: {e}[/red]")
    
    def _format_event(self, event: PolicyEvent) -> None:
        """Format and display an event."""
        # Build formatted string
        direction = f"[magenta]{event.direction:8}[/magenta]" if event.is_egress else f"[blue]{event.direction:8}[/blue]"
        
        if event.verdict_str == "ALLOW":
            self.allow_count += 1
            verdict = "[green]ALLOW[/green]"
            symbol = "[green]✓[/green]"
        else:
            self.deny_count += 1
            verdict = "[red]DENY[/red]"
            symbol = "[red]✗[/red]"
        
        # Highlight based on known IPs
        src_color = "green" if "10.0.0.20" in event.src_ip else ("red" if "10.0.0.30" in event.src_ip else "white")
        dest_color = "yellow" if "10.0.0.10" in event.dest_ip else "white"
        
        src = f"[{src_color}]{event.src_ip}:{event.src_port}[/{src_color}]"
        dest = f"[{dest_color}]{event.dest_ip}:{event.dest_port}[/{dest_color}]"
        
        # Format runtime in microseconds
        runtime_us = event.runtime_ns / 1000.0
        runtime_str = f"[cyan]{runtime_us:>6.1f}µs[/cyan]"
        
        msg = f"{symbol} {direction} {verdict} {src} → {dest} ({event.protocol_name}) {runtime_str}"
        self.write(msg)
    
    async def stop_consumer(self) -> None:
        """Stop the ring buffer consumer."""
        if self.read_task:
            self.read_task.cancel()
            try:
                await self.read_task
            except asyncio.CancelledError:
                pass
            self.read_task = None
        
        if self.consumer:
            await self.consumer.stop()
            self.consumer = None
        
        try:
            self.write("[dim]Ring buffer consumer stopped[/dim]")
        except Exception:
            pass


class ControlPanel(Container):
    """Control panel with buttons for actions."""
    
    def compose(self) -> ComposeResult:
        """Create the control panel layout."""
        yield Static("[bold cyan]═══ Control Panel ═══[/bold cyan]", classes="panel-title")
        
        yield Static("[bold yellow]Setup & Config[/bold yellow]", classes="section-title")
        with Container(classes="button-grid"):
            yield Button("Setup", id="btn_full_setup", variant="primary")
            yield Static("")  # Spacer
            yield Static("")  # Spacer
        
        # Architecture diagram
        yield Static("[green]┌──────────────┐[/green]              [yellow]┌──────────────┐[/yellow]")
        yield Static("[green]│   ALLOWED    │[/green]              [yellow]│   BACKEND    │[/yellow]")
        yield Static("[green]│  10.0.0.20   │[/green]  [green]✓ ALLOW[/green] ──► [yellow]│  10.0.0.10   │[/yellow]")
        yield Static("[green]│  (allowed)   │[/green]              [yellow]│   :8080      │[/yellow]")
        yield Static("[green]└──────────────┘[/green]              [yellow]└──────────────┘[/yellow]")
        yield Static("                                     [yellow]▲[/yellow]")
        yield Static("[red]┌──────────────┐[/red]                     [yellow]│[/yellow]")
        yield Static("[red]│   DENIED     │[/red]                     [yellow]│[/yellow]")
        yield Static("[red]│  10.0.0.30   │[/red] [red]✗ DENY[/red] ──────────X  [yellow]│[/yellow]")
        yield Static("[red]│   (denied)   │[/red]            [dim]BPF filters[/dim]")
        yield Static("[red]└──────────────┘[/red]")
        
        yield Static("[bold yellow]Testing[/bold yellow]", classes="section-title")
        with Container(classes="button-grid"):
            yield Button("Test Allowed", id="btn_test_allowed", disabled=True)
            yield Button("Test Denied", id="btn_test_denied", disabled=True)
            yield Static("")  # Spacer
        
        yield Static("[bold yellow]Monitor[/bold yellow]", classes="section-title")
        with Container(classes="button-grid"):
            yield Button("Setup Status", id="btn_show_status")
            yield Button("Network Status", id="btn_net_status")
            yield Button("Show Policies", id="btn_show_policies")
            yield Button("Stack Traces", id="btn_show_stacks")
            yield Static("")  # Spacer
            yield Static("")  # Spacer
        with Container(classes="button-grid"):
            yield Button("Clear Output", id="btn_clear_output")
            yield Button("Clear Trace", id="btn_clear_trace")
            yield Static("")  # Spacer


class OutputLog(Container):
    """Output log for command results."""
    
    DEFAULT_CSS = """
    OutputLog {
        layout: vertical;
        height: 100%;
    }
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.text_buffer = []  # Store plain text for copying
    
    def compose(self) -> ComposeResult:
        """Compose the output log."""
        with Horizontal():
            yield Static("[bold cyan]═══ Command Output ═══[/bold cyan]", classes="panel-title")
            yield Button("Save", id="btn_save_output", variant="default")
        yield RichLog(id="output_content", wrap=True, highlight=True, markup=True, max_lines=1000)
    
    def write(self, message: str) -> None:
        """Write a message to the log."""
        log = self.query_one("#output_content", RichLog)
        log.write(message)
        # Store plain text version (strip Rich markup)
        import re
        plain = re.sub(r'\[/?[^\]]+\]', '', message)
        self.text_buffer.append(plain)
    
    def clear(self) -> None:
        """Clear the log."""
        log = self.query_one("#output_content", RichLog)
        log.clear()
        self.text_buffer = []
    
    def get_text(self) -> str:
        """Get all text as plain string."""
        return '\n'.join(self.text_buffer)
    
    def log_success(self, message: str) -> None:
        """Log a success message."""
        self.write(f"[green][OK] {message}[/green]")
    
    def log_error(self, message: str) -> None:
        """Log an error message."""
        self.write(f"[red][ERROR] {message}[/red]")
    
    def log_info(self, message: str) -> None:
        """Log an info message."""
        self.write(f"[blue][INFO] {message}[/blue]")
    
    def log_warning(self, message: str) -> None:
        """Log a warning message."""
        self.write(f"[yellow][WARN] {message}[/yellow]")


class EBPFManagerApp(App):
    """Main TUI application."""
    
    CSS = """
    Screen {
        layout: vertical;
        height: 100vh;
    }
    
    #main_container {
        height: 1fr;
    }
    
    #control_panel {
        width: 35%;
        border: solid $primary;
        padding: 1;
        overflow-y: auto;
    }
    
    #right_panel {
        width: 65%;
    }
    
    .button-grid {
        layout: grid;
        grid-size: 3;
        grid-gutter: 1;
        margin: 0 0 1 0;
    }
    
    .section-title {
        padding: 1 0 1 0;
    }
    
    OutputLog {
        height: 1fr;
        border: solid $success;
    }
    
    OutputLog Horizontal {
        height: auto;
        padding: 0 1;
        background: $surface;
        align: right middle;
    }
    
    OutputLog .panel-title {
        width: 1fr;
        height: auto;
        padding: 1;
    }
    
    OutputLog Button {
        width: auto;
        min-width: 8;
        height: 1;
        padding: 0 2;
        margin: 0 0 0 1;
    }
    
    OutputLog RichLog {
        height: 1fr;
    }
    
    TracePipeLog {
        height: 1fr;
        border: solid $warning;
    }
    
    TracePipeLog Horizontal {
        height: auto;
        width: 100%;
    }
    
    TracePipeLog .panel-title {
        height: auto;
        padding: 1;
        background: $surface;
        width: 1fr;
    }
    
    TracePipeLog Button {
        height: auto;
        min-width: 12;
    }
    
    TracePipeLog RichLog {
        height: 1fr;
    }
    
    RingBufferLog {
        height: 1fr;
        border: solid $success;
    }
    
    RingBufferLog .panel-title {
        height: auto;
        padding: 1;
        background: $surface;
        width: 1fr;
    }
    
    RingBufferLog RichLog {
        height: 1fr;
    }
    
    StatusBar {
        height: auto;
        background: $primary-darken-2;
        color: $text;
        padding: 0 1;
    }
    
    Button {
        width: 100%;
        height: 3;
        min-height: 3;
        content-align: center middle;
    }
    
    Button:hover {
        background: $primary;
    }
    
    Button:focus {
        background: $accent;
        border: heavy $accent-lighten-2;
    }
    
    .panel-title {
        text-align: center;
    }
    
    RichLog {
        border: none;
        background: $surface;
        overflow-y: auto;
    }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("s", "setup", "Setup"),
        Binding("a", "test_allowed", "Test Allowed"),
        Binding("d", "test_denied", "Test Denied"),
    ]
    
    TITLE = "AWS EKS Network Policy Agent Simulator"
    
    def __init__(self):
        super().__init__()
        self.base_dir = Path.cwd()
        self.env_mgr = EnvironmentManager(self.base_dir)
        self.net_mgr = None  # Will be initialized in on_mount with output log
        self.bpf_mgr = None  # Will be initialized in on_mount after net_mgr
        
        # Track backend server process
        self.backend_server_proc = None
        
        # Track setup completion
        self.setup_completed = False
    
    def compose(self) -> ComposeResult:
        """Create the application layout."""
        yield Header()
        
        with Horizontal(id="main_container"):
            yield ControlPanel(id="control_panel")
            with Vertical(id="right_panel"):
                yield OutputLog(id="output_log")
                yield RingBufferLog(id="ringbuf_log")
                yield BPFStatsMonitor(id="bpf_stats")
        
        yield StatusBar()
        yield Footer()
    
    async def on_mount(self) -> None:
        """Handle mount event."""
        output = self.query_one("#output_log", OutputLog)
        
        # Initialize network manager with output log so it can write to TUI
        self.net_mgr = MultiPodNetworkManager(output=output)
        
        # Initialize BPF manager with backend interface AND output log
        self.bpf_mgr = BPFManager(self.net_mgr.backend.veth_host, output=output)
        
        output.write("[bold cyan]AWS EKS Network Policy Agent Simulator[/bold cyan]")
        output.write("[dim]Press 's' to run Setup, or use the buttons below[/dim]")
        output.write("")
        
        # Check root
        if not self.env_mgr.check_root():
            output.log_error("Must run as root (use sudo)")
            output.write("")
        else:
            output.log_success("Running as root")
            output.write("")
            
            # Ring buffer consumer will be started after BPF programs are loaded
        
        # Small delay to ensure widgets are mounted
        await asyncio.sleep(0.1)
    
    async def on_unmount(self) -> None:
        """Cleanup when app is closing."""
        # Stop BPF stats monitoring (disables kernel stats gathering)
        try:
            stats_monitor = self.query_one("#bpf_stats", BPFStatsMonitor)
            await stats_monitor.stop_monitoring()
        except Exception:
            pass
        
        # Stop ring buffer consumer
        try:
            ringbuf_log = self.query_one("#ringbuf_log", RingBufferLog)
            await ringbuf_log.stop_consumer()
        except Exception:
            pass
        
        # Unload BPF programs (remove TC filters and pinned maps)
        try:
            if self.bpf_mgr:
                await asyncio.to_thread(self.bpf_mgr.unload)
        except Exception:
            pass
        
        # Stop stack trace capture
        try:
            if is_tc_capture_running():
                await asyncio.to_thread(stop_tc_stack_capture)
        except Exception:
            pass
    
    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press events."""
        button_id = event.button.id
        output = self.query_one("#output_log", OutputLog)
        
        # Show which button was pressed
        button_text = event.button.label
        output.write(f"\n[bold cyan]>>> Action: {button_text}[/bold cyan]")
        
        handlers = {
            "btn_full_setup": self.action_setup,
            "btn_show_policies": self.show_policies,
            "btn_test_allowed": self.test_allowed_client,
            "btn_test_denied": self.test_denied_client,
            "btn_show_status": self.show_status,
            "btn_net_status": self.show_network_status,
            "btn_clear_output": self.clear_output_log,
            "btn_clear_trace": self.clear_trace_log,
            "btn_save_output": self.save_output,
            "btn_show_stacks": self.show_stack_traces,
        }
        
        handler = handlers.get(button_id)
        if handler:
            await handler()
    
    async def setup_environment(self, step_num: int = 1) -> None:
        """Setup system environment."""
        output = self.query_one("#output_log", OutputLog)
        output.write(f"[bold blue]Step {step_num}: Environment Check[/bold blue]")
        output.write("[bold yellow]Objective:[/bold yellow] Verify root access and required tools")
        output.write("[cyan]$ whoami[/cyan]")
        output.write("[cyan]$ which clang bpftool tc ip[/cyan]")
        output.write("")
        
        # Check root
        if not self.env_mgr.check_root():
            output.log_error("Must run as root (use sudo)")
            output.write("")
            return
        output.write("[green]✓ Running as root[/green]")
        
        # Check dependencies
        present, missing = await asyncio.to_thread(self.env_mgr.check_dependencies)
        
        for tool in present:
            output.write(f"[green]✓ {tool} found[/green]")
        
        if missing:
            output.write("")
            for tool in missing:
                output.log_error(f"{tool} not found")
            output.write("[yellow]Run setup.sh to install missing tools[/yellow]")
            output.write("")
            return
        
        # Check ASM symlink
        asm_exists = await asyncio.to_thread(lambda: Path("/usr/include/asm").exists())
        if asm_exists:
            output.write("[green]✓ ASM headers configured[/green]")
        else:
            output.write("[yellow]⚠ ASM symlink missing (will create if needed)[/yellow]")
        
        output.write("")
        output.log_success("Validation: All required tools present")
        output.write("")
    
    async def setup_network(self, step_num: int = 2) -> None:
        """Setup network."""
        output = self.query_one("#output_log", OutputLog)
        output.write(f"[bold blue]Step {step_num}: Multi-Pod Network[/bold blue]")
        output.write("[bold yellow]Objective:[/bold yellow] Create 3-pod network (backend, allowed-client, denied-client)")
        output.write("")
        
        # Stop backend server before cleaning up network (since cleanup deletes namespaces)
        if self.backend_server_proc and self.backend_server_proc.poll() is None:
            output.write("[dim]Stopping existing backend server...[/dim]")
            self.backend_server_proc.terminate()
            try:
                await asyncio.wait_for(
                    asyncio.to_thread(self.backend_server_proc.wait),
                    timeout=2.0
                )
            except asyncio.TimeoutError:
                self.backend_server_proc.kill()
        
        # Clear the process reference since we're recreating the namespace
        self.backend_server_proc = None
        
        result = await asyncio.to_thread(self.net_mgr.setup_network)
        
        if result:
            output.write("")
            output.log_success(f"Validation: Multi-pod network configured")
            output.write("[bold cyan]Network Summary:[/bold cyan]")
            output.write(f"  Bridge: {self.net_mgr.host_bridge} ({self.net_mgr.host_bridge_ip})")
            output.write(f"  Backend: {self.net_mgr.backend.ip.split('/')[0]} (ns-backend, veth-be-h/p, port 8080)")
            output.write(f"  Allowed: {self.net_mgr.allowed_client.ip.split('/')[0]} (ns-allowed, veth-al-h/p)")
            output.write(f"  Denied: {self.net_mgr.denied_client.ip.split('/')[0]} (ns-denied, veth-de-h/p)")
            status = self.query_one(StatusBar)
            status.network_ready = True
        else:
            output.log_error("Validation: Network setup failed")
        output.write("")
    
    async def compile_program(self, step_num: int = 3) -> None:
        """Compile BPF program - delegates to bpf manager."""
        output = self.query_one("#output_log", OutputLog)
        output.write(f"[bold blue]Step {step_num}: Compile AWS VPC CNI BPF[/bold blue]")
        output.write("[bold yellow]Objective:[/bold yellow] Compile AWS VPC CNI eBPF program")
        output.write(f"[dim]Source: ebpf/c/tc.v4ingress.bpf.c[/dim]")
        output.write(f"[cyan]$ clang -O2 -target bpf -c tc.v4ingress.bpf.c -o tc.v4ingress.bpf.o[/cyan]")
        
        result = await asyncio.to_thread(self.bpf_mgr.compile)
        
        if result:
            output.log_success(f"Validation: Compilation successful - {self.bpf_mgr.obj_file.name if self.bpf_mgr.obj_file else 'object file'} created")
        else:
            output.log_error("Validation: Compilation failed")
        output.write("")
    
    async def load_program(self, step_num: int = 4) -> None:
        """Load BPF program - delegates to bpf manager."""
        output = self.query_one("#output_log", OutputLog)
        output.write(f"[bold blue]Step {step_num}: Load BPF to Backend[/bold blue]")
        output.write("[bold yellow]Objective:[/bold yellow] Load and attach ingress & egress eBPF programs")
        output.write("")
        
        result = await asyncio.to_thread(self.bpf_mgr.load_and_attach)
        
        if result:
            output.log_success(f"Validation: Program loaded on {self.net_mgr.backend.veth_host} - ID {self.bpf_mgr.program_id}")
            if self.bpf_mgr.egress_program_id:
                output.write(f"[cyan]  Egress Program ID: {self.bpf_mgr.egress_program_id}[/cyan]")
            if self.bpf_mgr.map_id:
                output.write(f"[cyan]  Map ID: {self.bpf_mgr.map_id}[/cyan]")
            status = self.query_one(StatusBar)
            status.program_id = self.bpf_mgr.program_id
            status.map_id = self.bpf_mgr.map_id
            
            # Start BPF performance monitoring (bpftop-style)
            output.write("")
            output.write("[bold magenta]═══ BPF Performance Monitoring ═══[/bold magenta]")
            output.write("[dim]Starting bpftop-style performance monitor...[/dim]")
            
            try:
                stats_monitor = self.query_one("#bpf_stats", BPFStatsMonitor)
                stats_monitor.set_program_ids(
                    self.bpf_mgr.program_id,
                    self.bpf_mgr.egress_program_id
                )
                await stats_monitor.start_monitoring()
                output.log_success("BPF stats monitoring started")
                output.write("[dim]  Live stats shown in the performance panel above[/dim]")
            except Exception as e:
                output.log_error(f"Stats monitoring failed: {e}")
            
            # Start TC-level stack trace capture
            output.write("")
            output.write("[bold cyan]═══ Stack Trace Capture (cls_bpf_classify kprobe) ═══[/bold cyan]")
            output.write("[dim]Attaching kprobe to capture stacks at TC BPF decision point...[/dim]")
            
            try:
                # Stop any existing capture first
                if is_tc_capture_running():
                    await asyncio.to_thread(stop_tc_stack_capture)
                
                success = await asyncio.to_thread(start_tc_stack_capture)
                if success:
                    output.log_success("Stack trace kprobe loaded (cls_bpf_classify)")
                    output.write("[dim]  Use '📊 Stacks' button to view captured stack traces[/dim]")
                else:
                    output.log_error("Failed to load stack trace kprobe")
                    output.write("[dim]  BCC may not be installed or cls_bpf_classify not available[/dim]")
            except Exception as e:
                output.log_error(f"Stack trace kprobe failed: {e}")
        else:
            output.log_error("Validation: Failed to load program")
        
        output.write("")
    
    async def show_network_status(self) -> None:
        """Show network configuration."""
        output = self.query_one("#output_log", OutputLog)
        output.write("[bold yellow]Objective:[/bold yellow] Display pod network topology")
        output.write("")
        
        # Network topology diagram
        output.write("[bold cyan]Network Topology Diagram:[/bold cyan]")
        output.write("")
        output.write("[dim]Host (root namespace)[/dim]")
        output.write("├── [cyan]br-sim[/cyan] (bridge, IP: 10.0.0.1/24)")
        output.write("│   ├── [yellow]veth-be-h[/yellow] [magenta]← BPF programs attached HERE[/magenta]")
        output.write("│   │   └────────────────┐")
        output.write("│   ├── [green]veth-al-h[/green] ────────┤ [dim](host-side veths on bridge)[/dim]")
        output.write("│   └── [red]veth-de-h[/red] ────────┤")
        output.write("│                         │")
        output.write("│                         │ [dim]veth pairs (virtual cables)[/dim]")
        output.write("│                         │")
        output.write("├── [yellow]ns-backend[/yellow] (namespace)│")
        output.write("│   └── [yellow]veth-be-p[/yellow] ────────┘ [dim](pod-side, IP: 10.0.0.10/24)[/dim]")
        output.write("│")
        output.write("├── [green]ns-allowed[/green] (namespace)")
        output.write("│   └── [green]veth-al-p[/green] [dim](IP: 10.0.0.20/24)[/dim]")
        output.write("│")
        output.write("└── [red]ns-denied[/red] (namespace)")
        output.write("    └── [red]veth-de-p[/red] [dim](IP: 10.0.0.30/24)[/dim]")
        output.write("")
        output.write("[dim]Traffic flow: allowed-pod → veth-al-p → veth-al-h → br-sim → [/dim][magenta]veth-be-h (BPF)[/magenta][dim] → veth-be-p → backend-pod[/dim]")
        output.write("")
        output.write("[bold green]Key point:[/bold green] BPF attaches to [yellow]veth-be-h[/yellow] (host side), not the pod!")
        output.write("[dim]This way it stays attached even if pods restart. Host manages all policy enforcement.[/dim]")
        output.write("")
        
        # Bridge info
        output.write("[bold cyan]Bridge Details:[/bold cyan]")
        output.write(f"  Name: {self.net_mgr.host_bridge} [dim](br-sim = 'bridge-simulated')[/dim]")
        output.write(f"  IP: {self.net_mgr.host_bridge_ip}")
        output.write("")
        
        # Pod details with veth pairs
        output.write("[bold cyan]Pod Configuration:[/bold cyan]")
        for pod in self.net_mgr.pods:
            role_color = "yellow" if pod.role == "backend" else "green" if "allowed" in pod.role else "red"
            output.write(f"  [{role_color}]{pod.name.upper()}[/{role_color}] ({pod.role})")
            output.write(f"    IP: {pod.ip}")
            output.write(f"    Namespace: {pod.namespace}")
            output.write(f"    veth pair: {pod.veth_host} (host) ↔ {pod.veth_pod} (pod)")
            if pod.role == "backend":
                output.write(f"    [magenta]BPF programs attached to {pod.veth_host}[/magenta]")
            output.write("")
        
        # Show TC attachment
        output.write("[bold cyan]Traffic Control (TC) Attachment:[/bold cyan]")
        output.write(f"  Interface: {self.net_mgr.backend.veth_host}")
        output.write(f"  Ingress filter: tc.v4ingress.bpf.o → TC egress (checks SOURCE IP)")
        output.write(f"  Egress filter: tc.v4egress.bpf.o → TC ingress (checks DEST IP)")
        output.write("")
    
    async def initialize_maps(self) -> None:
        """Initialize BPF pod state maps."""
        output = self.query_one("#output_log", OutputLog)
        
        output.write("[bold yellow]Objective:[/bold yellow] Initialize pod state maps for AWS VPC CNI")
        output.write("[dim]Setting NETWORK_POLICY_KEY=0 and CLUSTER_NETWORK_POLICY_KEY=1 to DEFAULT_ALLOW[/dim]")
        
        try:
            result = await asyncio.to_thread(
                self.bpf_mgr.initialize_pod_state_maps
            )
            if result:
                output.log_success("Validation: Pod state maps initialized successfully")
            else:
                output.log_warning("Validation: Could not initialize maps (may work anyway)")
        except Exception as e:
            output.log_error(f"Validation: Failed to initialize maps: {e}")
        output.write("")
    
    async def start_backend_server(self, step_num: int = 5) -> None:
        """Start TCP server in backend pod."""
        output = self.query_one("#output_log", OutputLog)
        
        # Check if we have a running process AND the namespace still exists
        if self.backend_server_proc and self.backend_server_proc.poll() is None:
            # Verify the namespace still exists
            ns_check = await asyncio.to_thread(
                subprocess.run,
                ["ip", "netns", "list"],
                capture_output=True,
                text=True
            )
            if self.net_mgr.backend.namespace in ns_check.stdout:
                output.log_warning("Backend server already running")
                output.write("")
                return
            else:
                # Namespace doesn't exist anymore, clear the stale process
                self.backend_server_proc = None
        
        output.write(f"[bold blue]Step {step_num}: Start Backend Server[/bold blue]")
        output.write("[bold yellow]Objective:[/bold yellow] Start TCP server on backend pod port 8080")
        output.write(f"[cyan]$ ip netns exec {self.net_mgr.backend.namespace} nc -l -k -p 8080 &[/cyan]")
        
        try:
            self.backend_server_proc = await asyncio.to_thread(
                self.net_mgr.start_backend_server, 8080
            )
            output.log_success(f"Validation: Backend server started on {self.net_mgr.backend.ip.split('/')[0]}:8080")
        except Exception as e:
            output.log_error(f"Validation: Failed to start server: {e}")
        output.write("")
    
    async def stop_backend_server(self) -> None:
        """Stop TCP server in backend pod."""
        output = self.query_one("#output_log", OutputLog)
        output.write("[bold yellow]Objective:[/bold yellow] Stop backend TCP server")
        
        if self.backend_server_proc and self.backend_server_proc.poll() is None:
            self.backend_server_proc.terminate()
            try:
                await asyncio.wait_for(
                    asyncio.to_thread(self.backend_server_proc.wait),
                    timeout=2.0
                )
                output.log_success("Validation: Backend server stopped")
            except asyncio.TimeoutError:
                self.backend_server_proc.kill()
                output.log_warning("Server forcefully killed")
        else:
            output.log_warning("Backend server not running")
        output.write("")
    
    async def allow_client(self) -> None:
        """Add allowed-client IP to policy."""
        output = self.query_one("#output_log", OutputLog)
        ip = self.net_mgr.allowed_client.ip.split('/')[0]
        
        output.write(f"[bold yellow]Objective:[/bold yellow] Allow {ip} (allowed-client) to access backend")
        if self.bpf_mgr.map_id:
            output.write(f"[cyan]$ bpftool map update id {self.bpf_mgr.map_id} key hex 20000000{ip.replace('.', '')} value hex fe...[/cyan]")
        output.write(f"[cyan]$ bpftool map update id <pod_state_map_id> key 0x00000000 value 0x00[/cyan]")
        
        result = await asyncio.to_thread(self.bpf_mgr.add_allowed_ip, ip)
        
        if result:
            output.log_success(f"Validation: {ip} added to ingress_map (allowed)")
            
            # Enable strict policy enforcement (deny-by-default)
            output.write(f"[dim]Enabling deny-by-default policy...[/dim]")
            enforce_result = await asyncio.to_thread(self.bpf_mgr.enforce_policies)
            if enforce_result:
                output.log_success("Policy enforcement enabled - only allowed IPs can connect")
            else:
                output.log_warning("Could not enable strict enforcement")
        else:
            output.log_error("Validation: Failed to add IP")
        output.write("")
    
    async def block_client(self) -> None:
        """Remove allowed-client IP from policy."""
        output = self.query_one("#output_log", OutputLog)
        ip = self.net_mgr.allowed_client.ip.split('/')[0]
        
        output.write(f"[bold yellow]Objective:[/bold yellow] Block {ip} (allowed-client) from backend")
        if self.bpf_mgr.map_id:
            output.write(f"[cyan]$ bpftool map delete id {self.bpf_mgr.map_id} key hex 20000000{ip.replace('.', '')}[/cyan]")
        
        result = await asyncio.to_thread(self.bpf_mgr.remove_allowed_ip, ip)
        
        if result:
            output.log_success(f"Validation: {ip} removed from ingress_map (blocked)")
        else:
            output.log_error("Validation: Failed to remove IP")
        output.write("")
    
    async def show_policies(self) -> None:
        """Show current BPF policies."""
        output = self.query_one("#output_log", OutputLog)
        output.write("[bold yellow]Objective:[/bold yellow] Display ingress policy map contents")
        
        # Find map ID if not already set
        if not self.bpf_mgr.map_id:
            map_id = await asyncio.to_thread(self.bpf_mgr.find_map, "ingress_map")
            if map_id:
                self.bpf_mgr.map_id = map_id
        
        if self.bpf_mgr.map_id:
            output.write(f"[cyan]$ bpftool map dump id {self.bpf_mgr.map_id}[/cyan]")
        output.write("")
        
        # Get map contents
        map_contents = await asyncio.to_thread(self.bpf_mgr.dump_map)
        output.write("[cyan]Policy Map Contents:[/cyan]")
        output.write(map_contents)
        output.write("")
    
    async def test_allowed_client(self) -> None:
        """Test TCP connection from allowed-client to backend."""
        output = self.query_one("#output_log", OutputLog)
        
        if not self.setup_completed:
            output.log_error("Setup must be completed before testing")
            output.write("")
            return
        
        output.write(f"[bold yellow]Test:[/bold yellow] Allowed client ({self.net_mgr.allowed_client.ip.split('/')[0]}) → Backend ({self.net_mgr.backend.ip.split('/')[0]}:8080)")
        output.write(f"[cyan]$ ip netns exec {self.net_mgr.allowed_client.namespace} timeout 2 nc -zv {self.net_mgr.backend.ip.split('/')[0]} 8080[/cyan]")
        
        result = await asyncio.to_thread(
            self.net_mgr.test_tcp_connection, "allowed-client", 8080, 2
        )
        
        if result:
            output.write(f"[green][PASS] Allowed client can connect (expected)[/green]")
        else:
            output.write(f"[yellow][FAIL] Allowed client blocked (check policy)[/yellow]")
        output.write("")
    
    async def test_denied_client(self) -> None:
        """Test TCP connection from denied-client to backend."""
        output = self.query_one("#output_log", OutputLog)
        
        if not self.setup_completed:
            output.log_error("Setup must be completed before testing")
            output.write("")
            return
        
        output.write(f"[bold yellow]Test:[/bold yellow] Denied client ({self.net_mgr.denied_client.ip.split('/')[0]}) → Backend ({self.net_mgr.backend.ip.split('/')[0]}:8080)")
        output.write(f"[cyan]$ ip netns exec {self.net_mgr.denied_client.namespace} timeout 2 nc -zv {self.net_mgr.backend.ip.split('/')[0]} 8080[/cyan]")
        
        result = await asyncio.to_thread(
            self.net_mgr.test_tcp_connection, "denied-client", 8080, 2
        )
        
        if result:
            output.write(f"[yellow][FAIL] Denied client can connect (policy not enforced)[/yellow]")
        else:
            output.write(f"[green][PASS] Denied client blocked (expected)[/green]")
        output.write("")
    
    async def show_status(self) -> None:
        """Show comprehensive system status report."""
        output = self.query_one("#output_log", OutputLog)
        output.write("[bold yellow]Objective:[/bold yellow] Display comprehensive system status")
        output.write("")
        
        # Show comprehensive status report
        output.write("[bold cyan]=== System Status Report ===[/bold cyan]")
        report = await asyncio.to_thread(self.bpf_mgr.get_status_report, False)  # Don't print to console
        
        # Display status report in output log
        for step in report["steps"]:
            status_symbol = {
                "PASS": "✅",
                "FAIL": "❌",
                "WARN": "⚠️"
            }[step["status"]]
            
            output.write(f"\n[bold]Step {step['id']}: {step['name']}[/bold] {status_symbol} {step['status']}")
            for detail in step["details"]:
                output.write(f"  {detail}")
        
        # Overall status
        if report["overall_status"] == "PASS":
            output.write("\n[bold green]✅ Overall Status: PASS[/bold green]")
        elif report["overall_status"] == "WARN":
            output.write("\n[bold yellow]⚠️  Overall Status: PASS with warnings[/bold yellow]")
        else:
            output.write("\n[bold red]❌ Overall Status: FAIL[/bold red]")
        
        # Stack capture status
        output.write("\n[bold]Stack Trace Capture:[/bold]")
        if is_tc_capture_running():
            output.write("  [green]✓ TC kprobe active (cls_bpf_classify)[/green]")
            from .stacks import get_stack_capture_stats
            total, sampled, index = get_stack_capture_stats()
            output.write(f"  [dim]Stats: {total:,} packets seen, {sampled:,} sampled, {index} in buffer[/dim]")
        else:
            output.write("  [yellow]⚠ Not running - run Setup to start[/yellow]")
        
        output.write("")
    
    async def start_trace(self) -> None:
        """Start/restart ring buffer consumer."""
        ringbuf_log = self.query_one("#ringbuf_log", RingBufferLog)
        output = self.query_one("#output_log", OutputLog)
        
        if ringbuf_log.consumer and ringbuf_log.read_task:
            output.log_info("Restarting ring buffer consumer...")
            await ringbuf_log.stop_consumer()
        else:
            output.log_info("Starting ring buffer consumer...")
        
        await ringbuf_log.start_consumer()
        output.write("")
    
    async def stop_trace(self) -> None:
        """Stop ring buffer consumer."""
        ringbuf_log = self.query_one("#ringbuf_log", RingBufferLog)
        output = self.query_one("#output_log", OutputLog)
        
        output.log_info("Stopping ring buffer consumer...")
        await ringbuf_log.stop_consumer()
        output.write("")
    
    async def clear_output_log(self) -> None:
        """Clear command output log only."""
        output = self.query_one("#output_log", OutputLog)
        
        output.clear()
        output.write("[dim]Command output cleared[/dim]")
        output.write("")
    
    async def clear_trace_log(self) -> None:
        """Clear ring buffer event log only."""
        output = self.query_one("#output_log", OutputLog)
        ringbuf_log = self.query_one("#ringbuf_log", RingBufferLog)
        
        ringbuf_log.clear()
        output.write("[dim]Ring buffer event log cleared[/dim]")
        output.write("")
    
    async def save_output(self) -> None:
        """Save output log to file."""
        output = self.query_one("#output_log", OutputLog)
        text = output.get_text()
        
        from datetime import datetime
        filename = f"command_output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(filename, 'w') as f:
            f.write(text)
        
        output.log_success(f"Output saved to: {filename}")
    
    async def show_stack_traces(self) -> None:
        """Display kernel stack traces captured by BPF program."""
        output = self.query_one("#output_log", OutputLog)
        
        try:
            # Get stack traces as plain text
            result = get_stack_traces_text()
            
            if result.strip():
                for line in result.split('\n'):
                    output.write(line)
            else:
                output.write("No stack traces found. Generate traffic first.")
        except Exception as e:
            output.log_error(f"Failed to read stack traces: {e}")
    
    async def action_test_allowed(self) -> None:
        """Action handler for test allowed keyboard shortcut."""
        await self.test_allowed_client()
    
    async def action_test_denied(self) -> None:
        """Action handler for test denied keyboard shortcut."""
        await self.test_denied_client()
    
    async def action_setup(self) -> None:
        """Run full setup workflow."""
        output = self.query_one("#output_log", OutputLog)
        output.write("\n[bold green]=== Running Multi-Pod Setup ===[/bold green]")
        output.write("[cyan]Scenario: Backend service with ingress policy enforcement[/cyan]")
        output.write("")
        
        steps = [
            self.setup_environment,
            self.setup_network,
            self.compile_program,
            self.load_program,
            self.start_backend_server,
        ]
        
        for i, func in enumerate(steps, 1):
            await func(step_num=i)
        
        # Step 6: Configure allowed client policy
        output.write("[bold blue]Step 6: Configure Network Policies[/bold blue]")
        output.write("[bold yellow]Objective:[/bold yellow] Allow allowed-client, enforce deny-by-default")
        ip = self.net_mgr.allowed_client.ip.split('/')[0]
        
        # Get actual map IDs for display
        ingress_map_id = self.bpf_mgr.map_id if self.bpf_mgr.map_id else "<ingress_map_id>"
        pod_state_map_id = await asyncio.to_thread(self.bpf_mgr.find_map, "ingress_pod_state_map")
        if not pod_state_map_id:
            pod_state_map_id = "<pod_state_map_id>"
        
        output.write(f"[cyan]$ bpftool map update id {ingress_map_id} key {ip}/32[/cyan]")
        output.write(f"[cyan]$ bpftool map update id {pod_state_map_id} key 0x00000000 value 0x00[/cyan]")
        
        # Add allowed client
        result = await asyncio.to_thread(self.bpf_mgr.add_allowed_ip, ip)
        if result:
            output.log_success(f"Validation: {ip} added to ingress_map (allowed)")
            
            # Enable strict policy enforcement (deny-by-default)
            enforce_result = await asyncio.to_thread(self.bpf_mgr.enforce_policies)
            if enforce_result:
                output.log_success("Policy enforcement enabled - deny-by-default active")
            else:
                output.log_warning("Could not enable strict enforcement")
        else:
            output.log_error("Validation: Failed to add IP")
        output.write("")
        
        output.write("\n[bold green]=== Setup Complete ===[/bold green]")
        output.write("[cyan]Network configured with policies:[/cyan]")
        output.write(f"  - Allowed client ({self.net_mgr.allowed_client.ip.split('/')[0]}) can connect")
        output.write(f"  - Denied client ({self.net_mgr.denied_client.ip.split('/')[0]}) is blocked")
        output.write("[cyan]Ready to test:[/cyan]")
        output.write("  1. Click 'Test Allowed' (or press 'a') - should succeed")
        output.write("  2. Click 'Test Denied' (or press 'd') - should fail (blocked)")
        output.write("")
        
        # Show comprehensive status report
        output.write("\n[bold cyan]=== System Status Report ===[/bold cyan]")
        report = await asyncio.to_thread(self.bpf_mgr.get_status_report, False)  # Don't print to console
        
        # Display status report in output log
        for step in report["steps"]:
            status_symbol = {
                "PASS": "✅",
                "FAIL": "❌",
                "WARN": "⚠️"
            }[step["status"]]
            
            output.write(f"\n[bold]Step {step['id']}: {step['name']}[/bold] {status_symbol} {step['status']}")
            for detail in step["details"]:
                output.write(f"  {detail}")
        
        # Overall status
        if report["overall_status"] == "PASS":
            output.write("\n[bold green]✅ Overall Status: PASS[/bold green]")
        elif report["overall_status"] == "WARN":
            output.write("\n[bold yellow]⚠️  Overall Status: PASS with warnings[/bold yellow]")
        else:
            output.write("\n[bold red]❌ Overall Status: FAIL[/bold red]")
        output.write("")
        
        # Print setup complete AFTER status report
        output.write("\n[bold green]=== Setup Complete ===[/bold green]")
        output.write("[cyan]Network configured with policies:[/cyan]")
        output.write(f"  - Allowed client ({self.net_mgr.allowed_client.ip.split('/')[0]}) can connect")
        output.write(f"  - Denied client ({self.net_mgr.denied_client.ip.split('/')[0]}) is blocked")
        output.write("[cyan]Ready to test:[/cyan]")
        output.write("  1. Click 'Test Allowed' (or press 'a') - should succeed")
        output.write("  2. Click 'Test Denied' (or press 'd') - should fail (blocked)")
        output.write("")
        
        # Mark setup as completed and enable test buttons
        self.setup_completed = True
        self.query_one("#btn_test_allowed", Button).disabled = False
        self.query_one("#btn_test_denied", Button).disabled = False
        
        # Start ring buffer consumer now that BPF is loaded
        try:
            ringbuf_log = self.query_one("#ringbuf_log", RingBufferLog)
            await ringbuf_log.start_consumer()
        except Exception as e:
            output.write(f"[yellow]Ring buffer: {e}[/yellow]")
    
    async def action_toggle_trace(self) -> None:
        """Toggle ring buffer consumer."""
        ringbuf_log = self.query_one("#ringbuf_log", RingBufferLog)
        
        if ringbuf_log.consumer and ringbuf_log.read_task:
            await ringbuf_log.stop_consumer()
        else:
            await ringbuf_log.start_consumer()
    
    async def action_quit(self) -> None:
        """Clean up and quit the application."""
        # Unload BPF programs (remove TC filters and pinned maps)
        try:
            if self.bpf_mgr:
                await asyncio.to_thread(self.bpf_mgr.unload)
        except Exception:
            pass
        
        # Stop BPF stats monitoring
        try:
            stats_monitor = self.query_one("#bpf_stats", BPFStatsMonitor)
            await stats_monitor.stop_monitoring()
        except Exception:
            pass
        
        # Stop ring buffer consumer
        try:
            ringbuf_log = self.query_one("#ringbuf_log", RingBufferLog)
            await ringbuf_log.stop_consumer()
        except Exception:
            pass
        
        # Stop stack trace capture
        try:
            if is_tc_capture_running():
                await asyncio.to_thread(stop_tc_stack_capture)
        except Exception:
            pass
        
        # Now quit
        self.exit()


def run_tui() -> None:
    """Run the TUI application."""
    app = EBPFManagerApp()
    app.run()


if __name__ == "__main__":
    run_tui()
