"""Stack trace utilities for BPF programs.

Captures kernel stack traces at the TC BPF classification point (cls_bpf_classify),
which is where your TC eBPF program makes allow/deny decisions.
"""

import subprocess
import re
import os
from typing import Optional, List, Tuple, Dict
from rich.console import Console
from rich.table import Table

console = Console()

# Cache kallsyms to avoid repeated sudo calls
_kallsyms_cache: Optional[List[Tuple[int, str]]] = None

# BCC program for TC-level stack capture
_TC_STACK_CAPTURE_PROG = """
#include <uapi/linux/ptrace.h>

BPF_STACK_TRACE(stack_traces, 1024);
BPF_ARRAY(stack_capture_count, u64, 3);
BPF_ARRAY(recent_stack_ids, u32, 64);

// Attach to cls_bpf_classify - called for each packet through TC BPF
int trace_tc_classify(struct pt_regs *ctx) {
    u32 total_key = 0, sample_key = 1, index_key = 2;
    u64 *total_count, *sample_count, *write_index;
    u64 new_total = 1, new_sample = 1, new_index = 0;
    
    // Increment total counter
    total_count = stack_capture_count.lookup(&total_key);
    if (total_count) new_total = *total_count + 1;
    stack_capture_count.update(&total_key, &new_total);
    
    // Sample every 2nd packet for quick results
    if (new_total % 2 != 0) return 0;
    
    // Capture stack
    int stack_id = stack_traces.get_stackid(ctx, BPF_F_FAST_STACK_CMP);
    if (stack_id < 0) return 0;
    
    // Increment sample counter  
    sample_count = stack_capture_count.lookup(&sample_key);
    if (sample_count) new_sample = *sample_count + 1;
    stack_capture_count.update(&sample_key, &new_sample);
    
    // Store in ring buffer
    write_index = stack_capture_count.lookup(&index_key);
    if (write_index) new_index = *write_index;
    
    u32 ring_idx = (u32)(new_index % 64);
    u32 sid = (u32)stack_id;
    recent_stack_ids.update(&ring_idx, &sid);
    
    new_index++;
    stack_capture_count.update(&index_key, &new_index);
    
    return 0;
}
"""

# Global to track if TC capture is running
_tc_capture_pid: Optional[int] = None


def start_tc_stack_capture() -> bool:
    """Start TC-level stack trace capture using BCC.
    
    Attaches a kprobe to cls_bpf_classify to capture stacks at the exact
    point where TC BPF programs make allow/deny decisions.
    
    Returns:
        True if successfully started, False otherwise
    """
    global _tc_capture_pid
    
    try:
        from bcc import BPF
    except ImportError:
        console.print("[red]BCC not installed. Cannot start TC stack capture.[/red]")
        console.print("[dim]Install with: pip install bcc[/dim]")
        return False
    
    try:
        # Fork a child process to run the BCC capture
        pid = os.fork()
        if pid == 0:
            # Child process
            try:
                b = BPF(text=_TC_STACK_CAPTURE_PROG)
                # Try cls_bpf_classify first, fall back to tcf_classify
                try:
                    b.attach_kprobe(event="cls_bpf_classify", fn_name="trace_tc_classify")
                except Exception:
                    b.attach_kprobe(event="tcf_classify", fn_name="trace_tc_classify")
                
                # Keep running
                import time
                while True:
                    time.sleep(60)
            except Exception:
                os._exit(1)
        else:
            # Parent process
            _tc_capture_pid = pid
            return True
    except Exception as e:
        return False


def stop_tc_stack_capture() -> None:
    """Stop TC-level stack trace capture.
    
    When the child process is killed, BCC automatically unloads the
    kprobe and cleans up all BPF resources (maps, programs).
    """
    global _tc_capture_pid
    
    if _tc_capture_pid:
        try:
            os.kill(_tc_capture_pid, 9)
        except Exception:
            pass
        _tc_capture_pid = None


def is_tc_capture_running() -> bool:
    """Check if TC capture is running."""
    global _tc_capture_pid
    if _tc_capture_pid:
        try:
            os.kill(_tc_capture_pid, 0)  # Check if process exists
            return True
        except OSError:
            _tc_capture_pid = None
    return False


def _load_kallsyms() -> List[Tuple[int, str]]:
    """Load kallsyms using sudo and cache it."""
    global _kallsyms_cache
    if _kallsyms_cache is not None:
        return _kallsyms_cache
    
    try:
        result = subprocess.run(
            ['sudo', 'cat', '/proc/kallsyms'],
            capture_output=True,
            text=True,
            check=True
        )
        
        symbols = []
        for line in result.stdout.split('\n'):
            parts = line.strip().split(maxsplit=2)
            if len(parts) >= 3:
                try:
                    sym_addr = int(parts[0], 16)
                    sym_name = parts[2].split()[0]  # Get just the symbol name, not module
                    if sym_addr > 0:
                        symbols.append((sym_addr, sym_name))
                except ValueError:
                    pass
        
        # Sort by address for binary search
        symbols.sort(key=lambda x: x[0])
        _kallsyms_cache = symbols
        return symbols
    except Exception:
        return []


def get_symbol(addr: str) -> str:
    """Resolve kernel address to symbol using /proc/kallsyms."""
    try:
        addr_int = int(addr, 16)
        symbols = _load_kallsyms()
        
        if not symbols:
            return f"0x{addr}"
        
        # Binary search for closest symbol <= addr
        left, right = 0, len(symbols) - 1
        best_match = None
        
        while left <= right:
            mid = (left + right) // 2
            if symbols[mid][0] <= addr_int:
                best_match = symbols[mid]
                left = mid + 1
            else:
                right = mid - 1
        
        if best_match:
            offset = addr_int - best_match[0]
            if offset == 0:
                return best_match[1]
            else:
                return f"{best_match[1]}+0x{offset:x}"
        
        return f"0x{addr}"
    except Exception:
        return f"0x{addr}"


def parse_stack_trace(stack_id: int) -> Optional[List[str]]:
    """Parse a stack trace from the BPF map."""
    addresses = []
    
    # Try pinned map first
    try:
        result = subprocess.run(
            ['sudo', 'bpftool', 'map', 'lookup', 'pinned', '/sys/fs/bpf/stack_traces', 
             'key', 'hex'] + [f'{(stack_id >> (8*i)) & 0xff:02x}' for i in range(4)],
            capture_output=True,
            text=True,
            check=True
        )
        addresses = _parse_stack_output(result.stdout)
        if addresses:
            return addresses
    except Exception:
        pass
    
    # Try all matching maps by name (for BCC maps - may have multiple)
    map_ids = _find_map_ids('stack_traces')
    for map_id in map_ids:
        try:
            result = subprocess.run(
                ['sudo', 'bpftool', 'map', 'lookup', 'id', str(map_id), 
                 'key', 'hex'] + [f'{(stack_id >> (8*i)) & 0xff:02x}' for i in range(4)],
                capture_output=True,
                text=True,
                check=True
            )
            addresses = _parse_stack_output(result.stdout)
            if addresses:
                return addresses
        except Exception:
            pass
    
    return None


def _parse_stack_output(output: str) -> List[str]:
    """Parse bpftool map lookup output to extract stack addresses."""
    if 'value' not in output:
        return []
    
    # Extract all hex bytes after "value:"
    lines = output.split('\n')
    hex_bytes = []
    in_value = False
    for line in lines:
        if 'value:' in line:
            in_value = True
            # Get hex bytes from the same line if any
            after_value = line.split('value:')[1]
            hex_bytes.extend(after_value.split())
        elif in_value and line.strip():
            # Continue collecting hex bytes from subsequent lines
            parts = line.strip().split()
            # Filter out any non-hex parts
            for part in parts:
                if all(c in '0123456789abcdefABCDEF' for c in part) and len(part) == 2:
                    hex_bytes.append(part)
    
    # Parse as little-endian 64-bit addresses (8 bytes each)
    addresses = []
    for i in range(0, len(hex_bytes), 8):
        if i + 7 < len(hex_bytes):
            # Combine 8 bytes into 64-bit address (little-endian)
            addr_bytes = hex_bytes[i:i+8]
            addr = 0
            for j in range(8):
                byte_val = int(addr_bytes[j], 16)
                addr |= (byte_val << (j * 8))
            
            if addr != 0:  # Skip null entries
                addresses.append(f"{addr:016x}")
    
    return addresses


def _find_map_ids(map_name: str) -> List[int]:
    """Find all BPF map IDs matching a name.
    
    Args:
        map_name: Name of the map to find (will be truncated to 15 chars)
    
    Returns:
        List of Map IDs matching the name, sorted descending (newest first)
    """
    try:
        result = subprocess.run(
            ['sudo', 'bpftool', 'map', 'list', '-j'],
            capture_output=True,
            text=True,
            check=True
        )
        import json
        maps = json.loads(result.stdout)
        
        # BPF map names are truncated to 15 chars
        search_name = map_name[:15]
        
        # Return all matching IDs, sorted descending
        matching_ids = []
        for m in maps:
            if m.get('name', '').startswith(search_name):
                matching_ids.append(m['id'])
        
        matching_ids.sort(reverse=True)
        return matching_ids
    except Exception:
        return []


def _find_map_id(map_name: str) -> Optional[int]:
    """Find a BPF map ID by name.
    
    Args:
        map_name: Name of the map to find (will be truncated to 15 chars)
    
    Returns:
        Map ID if found, None otherwise
    """
    ids = _find_map_ids(map_name)
    return ids[0] if ids else None


def get_recent_stacks_from_map() -> List[int]:
    """Get recent stack IDs directly from the BPF ring buffer map.
    
    Returns:
        List of unique stack_ids
    """
    stack_ids = set()
    
    def _parse_entries(entries):
        for entry in entries:
            if isinstance(entry, dict):
                # Handle formatted output from bpftool -j
                if 'formatted' in entry:
                    val = entry['formatted'].get('value')
                else:
                    val = entry.get('value')
                
                if isinstance(val, int) and val > 0:
                    stack_ids.add(val)
    
    # Try pinned map first
    try:
        result = subprocess.run(
            ['sudo', 'bpftool', 'map', 'dump', 'pinned', '/sys/fs/bpf/recent_stack_ids', '-j'],
            capture_output=True,
            text=True,
            check=True
        )
        import json
        entries = json.loads(result.stdout)
        _parse_entries(entries)
    except Exception:
        pass
    
    # Also try finding map by name (for BCC maps)
    if not stack_ids:
        map_id = _find_map_id('recent_stack_ids')
        if map_id:
            try:
                result = subprocess.run(
                    ['sudo', 'bpftool', 'map', 'dump', 'id', str(map_id), '-j'],
                    capture_output=True,
                    text=True,
                    check=True
                )
                import json
                entries = json.loads(result.stdout)
                _parse_entries(entries)
            except Exception:
                pass
    
    return list(stack_ids)


def get_stack_capture_stats() -> Tuple[int, int, int]:
    """Get stack capture statistics from the counter map.
    
    Returns:
        Tuple of (total_packets, sampled_packets, write_index)
    """
    stats = [0, 0, 0]
    
    def _parse_stats(entries):
        for entry in entries:
            if isinstance(entry, dict):
                # Handle formatted output from bpftool -j
                if 'formatted' in entry:
                    key = entry['formatted'].get('key')
                    val = entry['formatted'].get('value')
                elif 'key' in entry and 'value' in entry:
                    key = entry['key']
                    val = entry['value']
                else:
                    continue
                
                if isinstance(key, int) and isinstance(val, int) and 0 <= key <= 2:
                    stats[key] = val
    
    # Try pinned map first
    try:
        result = subprocess.run(
            ['sudo', 'bpftool', 'map', 'dump', 'pinned', '/sys/fs/bpf/stack_capture_count', '-j'],
            capture_output=True,
            text=True,
            check=True
        )
        import json
        entries = json.loads(result.stdout)
        _parse_stats(entries)
        if any(s > 0 for s in stats):
            return tuple(stats)
    except Exception:
        pass
    
    # Try finding map by name (for BCC maps)
    map_id = _find_map_id('stack_capture_c')
    if map_id:
        try:
            result = subprocess.run(
                ['sudo', 'bpftool', 'map', 'dump', 'id', str(map_id), '-j'],
                capture_output=True,
                text=True,
                check=True
            )
            import json
            entries = json.loads(result.stdout)
            _parse_stats(entries)
        except Exception:
            pass
    
    return tuple(stats)


def get_recent_stacks() -> List[Tuple[int, str, str]]:
    """Get recent stack traces - tries BPF map first, falls back to trace buffer.
    
    Returns:
        List of (stack_id, src_ip, dst_ip) tuples
    """
    # First try to read from the BPF ring buffer map
    stack_ids = get_recent_stacks_from_map()
    if stack_ids:
        return [(sid, "0x0", "0x0") for sid in stack_ids]
    
    # Fall back to trace buffer parsing
    try:
        result = subprocess.run(
            ['sudo', 'cat', '/sys/kernel/debug/tracing/trace'],
            capture_output=True,
            text=True,
            check=True
        )
        
        stacks = []
        for line in result.stdout.split('\n'):
            # Look for both TC and kprobe stack messages
            if '[STACK]' in line or '[KPROBE-STACK]' in line:
                # Extract: [STACK] Flow 0xXXXX->0xYYYY stack_id=NNN
                # Or: [KPROBE-STACK] IP: 0xXXXX->0xYYYY stack_id=NNN
                match = re.search(r'(0x[0-9a-f]+)->(0x[0-9a-f]+) stack_id=(\d+)', line)
                if match:
                    src_ip = match.group(1)
                    dst_ip = match.group(2)
                    stack_id = int(match.group(3))
                    stacks.append((stack_id, src_ip, dst_ip))
                else:
                    # Try simpler format: stack_id=NNN
                    match = re.search(r'stack_id=(\d+)', line)
                    if match:
                        stack_id = int(match.group(1))
                        stacks.append((stack_id, "0x0", "0x0"))
        
        return stacks
    except Exception:
        return []


def format_ip(hex_ip: str) -> str:
    """Convert hex IP (0x0a000014) to dotted notation (10.0.0.20)."""
    try:
        ip_int = int(hex_ip, 16)
        return f"{ip_int & 0xff}.{(ip_int >> 8) & 0xff}.{(ip_int >> 16) & 0xff}.{(ip_int >> 24) & 0xff}"
    except Exception:
        return hex_ip


def format_stack_trace_text(stack_id: int, max_depth: int = 20) -> List[str]:
    """Format a stack trace as plain text lines with annotations.
    
    Returns a list of plain text lines suitable for display in any context.
    """
    lines = []
    trace = parse_stack_trace(stack_id)
    if not trace:
        lines.append("  (stack data not available)")
        return lines
    
    for i, addr in enumerate(trace[:max_depth]):
        symbol = get_symbol(addr)
        # Add annotations for TC-related functions
        if 'cls_bpf' in symbol:
            lines.append(f"  #{i:2d}: {symbol}  ◀ YOUR TC BPF RUNS HERE")
        elif 'tcf_' in symbol or 'tc_run' in symbol:
            lines.append(f"  #{i:2d}: {symbol}  ◀ TC framework")
        elif 'netif_receive' in symbol or 'napi' in symbol:
            lines.append(f"  #{i:2d}: {symbol}  ◀ Network RX")
        else:
            lines.append(f"  #{i:2d}: {symbol}")
    
    if len(trace) > max_depth:
        lines.append(f"  ... ({len(trace) - max_depth} more frames)")
    
    return lines


def get_stack_traces_text() -> str:
    """Get all stack traces as plain text.
    
    Returns formatted text suitable for display in Textual or any terminal.
    """
    lines = []
    
    # Status
    if is_tc_capture_running():
        lines.append("✓ TC-level stack capture active")
    else:
        lines.append("⚠ TC capture not running")
    
    # Stats
    total, sampled, index = get_stack_capture_stats()
    if total > 0 or sampled > 0:
        lines.append(f"Stats: {total:,} TC packets, {sampled:,} sampled, {index} in buffer")
    
    lines.append("")
    
    stacks = get_recent_stacks()
    
    if not stacks:
        lines.append("No stack traces found.")
        lines.append("Generate traffic through TC to capture stack traces.")
        return "\n".join(lines)
    
    # Group by unique stack_id
    unique_stacks = {}
    for stack_id, src_ip, dst_ip in stacks:
        if stack_id not in unique_stacks:
            unique_stacks[stack_id] = (src_ip, dst_ip)
    
    lines.append(f"═══ TC-Level Kernel Stack Traces ({len(unique_stacks)} unique) ═══")
    lines.append("Captured at cls_bpf_classify - where your TC BPF program runs")
    lines.append("")
    
    for stack_id, (src_ip, dst_ip) in list(unique_stacks.items())[:5]:
        lines.append(f"Stack ID {stack_id}")
        lines.extend(format_stack_trace_text(stack_id))
        lines.append("")
    
    return "\n".join(lines)


def show_stack_traces():
    """Display all recent stack traces in a formatted table.
    
    Highlights TC BPF-related functions to show where your eBPF program runs.
    Uses plain text output for compatibility with Textual and all terminals.
    """
    print(get_stack_traces_text())


def capture_tc_stacks(duration: int = 5):
    """Convenience function to capture and display TC-level stack traces.
    
    Starts TC capture, waits for traffic, then shows results.
    
    Args:
        duration: How long to capture in seconds (default 5)
    """
    import time
    
    console.print(f"[bold cyan]Starting TC-level stack capture for {duration}s...[/bold cyan]")
    console.print("[dim]Generate traffic through your TC-attached interface during this time[/dim]\n")
    
    try:
        start_tc_stack_capture()
        
        # Wait for traffic with countdown
        for remaining in range(duration, 0, -1):
            console.print(f"[dim]Capturing... {remaining}s remaining[/dim]", end="\r")
            time.sleep(1)
        
        console.print(" " * 40, end="\r")  # Clear line
        
        # Stop capture
        stop_tc_stack_capture()
        
        # Give a moment for things to settle
        time.sleep(0.5)
        
        # Show results
        show_stack_traces()
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        stop_tc_stack_capture()
