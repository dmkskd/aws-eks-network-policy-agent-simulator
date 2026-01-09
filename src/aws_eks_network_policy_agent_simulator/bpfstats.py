"""BPF program performance statistics (bpftop-style).

Provides real-time monitoring of eBPF program performance metrics:
- Events per second
- Average runtime per invocation  
- Estimated CPU usage

Uses the kernel's BPF statistics gathering mechanism via
/proc/sys/kernel/bpf_stats_enabled and bpftool.
"""

import subprocess
import re
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class BPFProgramStats:
    """Statistics for a single BPF program."""
    program_id: int
    name: str
    prog_type: str
    run_time_ns: int = 0
    run_cnt: int = 0
    # Delta values (computed from samples)
    prev_run_time_ns: int = 0
    prev_run_cnt: int = 0
    last_sample_time: float = 0.0
    
    @property
    def events_per_sec(self) -> float:
        """Calculate events per second from delta."""
        if self.last_sample_time == 0:
            return 0.0
        delta_cnt = self.run_cnt - self.prev_run_cnt
        return delta_cnt  # Since we sample every 1 sec
    
    @property
    def avg_runtime_ns(self) -> float:
        """Calculate average runtime per event in ns."""
        delta_cnt = self.run_cnt - self.prev_run_cnt
        delta_time = self.run_time_ns - self.prev_run_time_ns
        if delta_cnt == 0:
            return 0.0
        return delta_time / delta_cnt
    
    @property
    def cpu_percent(self) -> float:
        """Estimate CPU percentage used by this program.
        
        CPU% = (run_time_ns delta / sample_interval_ns) * 100
        Assuming 1 second sample interval = 1_000_000_000 ns
        """
        delta_time = self.run_time_ns - self.prev_run_time_ns
        return (delta_time / 1_000_000_000) * 100


class BPFStatsCollector:
    """Collects performance statistics for BPF programs (bpftop-like).
    
    Uses the kernel's BPF statistics gathering mechanism:
    - Enables stats via /proc/sys/kernel/bpf_stats_enabled
    - Queries program stats using bpftool
    - Calculates events/sec, avg runtime, and CPU usage
    
    Example:
        collector = BPFStatsCollector()
        collector.enable_stats()
        
        # Sample every second
        while running:
            stats = collector.sample_programs([prog_id])
            print(f"Events/s: {stats[prog_id].events_per_sec}")
            time.sleep(1)
        
        collector.disable_stats()
    """
    
    def __init__(self):
        self.stats_enabled = False
        self.programs: dict[int, BPFProgramStats] = {}
        self._stats_fd: Optional[int] = None
    
    def enable_stats(self) -> bool:
        """Enable BPF statistics gathering in the kernel."""
        if self.stats_enabled:
            return True
        
        try:
            result = subprocess.run(
                ["sh", "-c", "echo 1 > /proc/sys/kernel/bpf_stats_enabled"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                self.stats_enabled = True
                return True
            return False
        except Exception:
            return False
    
    def disable_stats(self) -> bool:
        """Disable BPF statistics gathering."""
        if not self.stats_enabled:
            return True
        
        try:
            result = subprocess.run(
                ["sh", "-c", "echo 0 > /proc/sys/kernel/bpf_stats_enabled"],
                capture_output=True,
                text=True
            )
            self.stats_enabled = False
            return result.returncode == 0
        except Exception:
            return False
    
    def get_program_stats(self, program_id: int) -> Optional[BPFProgramStats]:
        """Get statistics for a specific BPF program.
        
        Args:
            program_id: The BPF program ID
            
        Returns:
            BPFProgramStats with current values, or None if not found
        """
        try:
            result = subprocess.run(
                ["bpftool", "prog", "show", "id", str(program_id)],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                return None
            
            output = result.stdout
            
            # Parse output - format varies:
            # "123: sched_cls  name handle_ingress  tag abc123  gpl run_time_ns 12345 run_cnt 100"
            
            # Extract program type and name
            prog_type = "unknown"
            name = "unknown"
            run_time_ns = 0
            run_cnt = 0
            
            # First line contains: "ID: TYPE  name NAME ..."
            first_line = output.split('\n')[0] if output else ""
            
            # Parse type (second word after ID:)
            type_match = re.search(r'^\d+:\s+(\w+)', first_line)
            if type_match:
                prog_type = type_match.group(1)
            
            # Parse name
            name_match = re.search(r'name\s+(\S+)', first_line)
            if name_match:
                name = name_match.group(1)
            
            # Parse run_time_ns and run_cnt
            time_match = re.search(r'run_time_ns\s+(\d+)', output)
            if time_match:
                run_time_ns = int(time_match.group(1))
            
            cnt_match = re.search(r'run_cnt\s+(\d+)', output)
            if cnt_match:
                run_cnt = int(cnt_match.group(1))
            
            # Update or create stats entry
            now = time.time()
            if program_id in self.programs:
                stats = self.programs[program_id]
                # Store previous values for delta calculation
                stats.prev_run_time_ns = stats.run_time_ns
                stats.prev_run_cnt = stats.run_cnt
                stats.run_time_ns = run_time_ns
                stats.run_cnt = run_cnt
                stats.last_sample_time = now
            else:
                stats = BPFProgramStats(
                    program_id=program_id,
                    name=name,
                    prog_type=prog_type,
                    run_time_ns=run_time_ns,
                    run_cnt=run_cnt,
                    prev_run_time_ns=run_time_ns,  # First sample, no delta
                    prev_run_cnt=run_cnt,
                    last_sample_time=now
                )
                self.programs[program_id] = stats
            
            return stats
            
        except Exception:
            return None
    
    def sample_programs(self, program_ids: list[int]) -> dict[int, BPFProgramStats]:
        """Sample statistics for multiple programs.
        
        Args:
            program_ids: List of program IDs to sample
            
        Returns:
            Dict mapping program ID to stats
        """
        results = {}
        for prog_id in program_ids:
            stats = self.get_program_stats(prog_id)
            if stats:
                results[prog_id] = stats
        return results
