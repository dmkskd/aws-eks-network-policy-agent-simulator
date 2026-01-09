"""BPF Ring Buffer consumer for policy events.

Consumes events from the policy_events ring buffer emitted by
the ingress/egress BPF programs. This replaces trace_pipe parsing
with structured event consumption.

The data_t struct from BPF:
    struct data_t {
        __u32  src_ip;
        __u32  src_port;
        __u32  dest_ip;
        __u32  dest_port;
        __u32  protocol;
        __u32  verdict;     // 0=DENY, 1=ALLOW
        __u32  packet_sz;
        __u8   is_egress;   // 0=ingress, 1=egress
        __u8   tier;        // 0=ERROR, 1=ADMIN, 2=NETWORK_POLICY, 3=BASELINE, 4=DEFAULT
    };
"""

import asyncio
import json
import struct
import socket
import subprocess
import os
from dataclasses import dataclass
from typing import Optional, Callable, List, AsyncIterator
from pathlib import Path
from enum import IntEnum


class Verdict(IntEnum):
    DENY = 0
    ALLOW = 1


class Tier(IntEnum):
    ERROR = 0
    ADMIN = 1
    NETWORK_POLICY = 2
    BASELINE = 3
    DEFAULT = 4


@dataclass
class PolicyEvent:
    """A policy decision event from BPF."""
    src_ip: str
    src_port: int
    dest_ip: str
    dest_port: int
    protocol: int  # 6=TCP, 17=UDP, 132=SCTP
    verdict: Verdict
    packet_size: int
    is_egress: bool
    tier: Tier
    runtime_ns: int = 0  # BPF program runtime in nanoseconds
    
    @property
    def protocol_name(self) -> str:
        """Human-readable protocol name."""
        protocols = {6: "TCP", 17: "UDP", 132: "SCTP", 1: "ICMP"}
        return protocols.get(self.protocol, str(self.protocol))
    
    @property
    def verdict_str(self) -> str:
        """Human-readable verdict."""
        return "ALLOW" if self.verdict == Verdict.ALLOW else "DENY"
    
    @property
    def direction(self) -> str:
        """Human-readable direction."""
        return "EGRESS" if self.is_egress else "INGRESS"
    
    @property
    def runtime_us(self) -> float:
        """Runtime in microseconds."""
        return self.runtime_ns / 1000.0
    
    @property
    def tier_name(self) -> str:
        """Human-readable tier name."""
        names = {
            Tier.ERROR: "ERROR",
            Tier.ADMIN: "ADMIN",
            Tier.NETWORK_POLICY: "NETWORK_POLICY",
            Tier.BASELINE: "BASELINE",
            Tier.DEFAULT: "DEFAULT",
        }
        return names.get(self.tier, str(self.tier))
    
    def __str__(self) -> str:
        return (
            f"[{self.direction}] {self.verdict_str} "
            f"{self.src_ip}:{self.src_port} → {self.dest_ip}:{self.dest_port} "
            f"({self.protocol_name}) tier={self.tier_name} size={self.packet_size} "
            f"time={self.runtime_us:.1f}µs"
        )


def ip_to_str(ip_int: int) -> str:
    """Convert integer IP to dotted-decimal string."""
    # IP is in network byte order (big-endian) stored as little-endian u32
    return socket.inet_ntoa(struct.pack('<I', ip_int))


def parse_event(data: bytes) -> Optional[PolicyEvent]:
    """Parse raw event bytes into PolicyEvent.
    
    struct data_t layout (32 bytes with padding):
        u32 src_ip       (0-3)
        u32 src_port     (4-7)
        u32 dest_ip      (8-11)
        u32 dest_port    (12-15)
        u32 protocol     (16-19)
        u32 verdict      (20-23)
        u32 packet_sz    (24-27)
        u8  is_egress    (28)
        u8  tier         (29)
        u8  padding[2]   (30-31) - compiler padding to 4-byte boundary
    """
    if len(data) < 30:
        return None
    
    try:
        # Unpack: 7 x u32, 2 x u8 (ignore padding)
        fields = struct.unpack('<IIIIIII B B', data[:30])
        
        return PolicyEvent(
            src_ip=ip_to_str(fields[0]),
            src_port=fields[1],
            dest_ip=ip_to_str(fields[2]),
            dest_port=fields[3],
            protocol=fields[4],
            verdict=Verdict(fields[5]),
            packet_size=fields[6],
            is_egress=bool(fields[7]),
            tier=Tier(fields[8]),
        )
    except Exception:
        return None


class RingBufferConsumer:
    """Consumes events from the BPF ring buffer.
    
    Uses bpftool to read from the pinned ring buffer map.
    For production, consider using libbpf Python bindings or BCC.
    """
    
    def __init__(self, map_path: str = "/sys/fs/bpf/policy_events"):
        self.map_path = map_path
        self._running = False
        self._callbacks: List[Callable[[PolicyEvent], None]] = []
        self._events: List[PolicyEvent] = []
        self._max_events = 1000  # Keep last N events
    
    @property
    def map_exists(self) -> bool:
        """Check if the ring buffer map is pinned."""
        return Path(self.map_path).exists()
    
    def add_callback(self, callback: Callable[[PolicyEvent], None]) -> None:
        """Add a callback to be called for each event."""
        self._callbacks.append(callback)
    
    def remove_callback(self, callback: Callable[[PolicyEvent], None]) -> None:
        """Remove a callback."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)
    
    def get_events(self) -> List[PolicyEvent]:
        """Get all captured events."""
        return list(self._events)
    
    def clear_events(self) -> None:
        """Clear captured events."""
        self._events.clear()
    
    def _process_event(self, event: PolicyEvent) -> None:
        """Process a single event."""
        # Store event
        self._events.append(event)
        if len(self._events) > self._max_events:
            self._events.pop(0)
        
        # Call callbacks
        for callback in self._callbacks:
            try:
                callback(event)
            except Exception:
                pass


class AsyncRingBufferConsumer:
    """Async consumer for BPF ring buffer events using the C helper program.
    
    Uses the ringbuf_consumer C program which outputs JSON events to stdout.
    This provides proper ring buffer polling via libbpf.
    """
    
    # Path to the C consumer binary (relative to project root)
    CONSUMER_PATH = Path(__file__).parent.parent.parent / "ebpf" / "c" / "ringbuf_consumer"
    
    def __init__(self, map_path: str = "/sys/fs/bpf/policy_events"):
        self.map_path = map_path
        self._process: Optional[asyncio.subprocess.Process] = None
        self._running = False
        self._callbacks: List[Callable[[PolicyEvent], None]] = []
        self._events: List[PolicyEvent] = []
        self._max_events = 1000
    
    @property
    def consumer_exists(self) -> bool:
        """Check if the C consumer binary exists."""
        return self.CONSUMER_PATH.exists()
    
    @property
    def map_exists(self) -> bool:
        """Check if the ring buffer map is pinned."""
        # Check with sudo since /sys/fs/bpf may not be readable
        try:
            result = subprocess.run(
                ["sudo", "test", "-e", self.map_path],
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def add_callback(self, callback: Callable[[PolicyEvent], None]) -> None:
        """Register a callback for new events."""
        self._callbacks.append(callback)
    
    def remove_callback(self, callback: Callable[[PolicyEvent], None]) -> None:
        """Remove a callback."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)
    
    def get_events(self) -> List[PolicyEvent]:
        """Get all captured events."""
        return list(self._events)
    
    def clear_events(self) -> None:
        """Clear captured events."""
        self._events.clear()
    
    def _parse_json_event(self, line: str) -> Optional[PolicyEvent]:
        """Parse a JSON event line from the C consumer."""
        try:
            data = json.loads(line)
            
            # Map protocol names back to numbers
            proto_map = {"TCP": 6, "UDP": 17, "SCTP": 132, "ICMP": 1}
            protocol = proto_map.get(data.get("protocol", ""), 0)
            
            # Map tier names back to enum
            tier_map = {
                "ERROR": Tier.ERROR,
                "ADMIN": Tier.ADMIN,
                "NETWORK_POLICY": Tier.NETWORK_POLICY,
                "BASELINE": Tier.BASELINE,
                "DEFAULT": Tier.DEFAULT,
            }
            tier = tier_map.get(data.get("tier", ""), Tier.ERROR)
            
            return PolicyEvent(
                src_ip=data.get("src_ip", "0.0.0.0"),
                src_port=data.get("src_port", 0),
                dest_ip=data.get("dest_ip", "0.0.0.0"),
                dest_port=data.get("dest_port", 0),
                protocol=protocol,
                verdict=Verdict.ALLOW if data.get("verdict") == "ALLOW" else Verdict.DENY,
                packet_size=data.get("size", 0),
                is_egress=data.get("direction") == "EGRESS",
                tier=tier,
                runtime_ns=data.get("runtime_ns", 0),
            )
        except (json.JSONDecodeError, KeyError, TypeError):
            return None
    
    async def start(self) -> bool:
        """Start the ring buffer consumer process."""
        if not self.consumer_exists:
            return False
        
        try:
            self._process = await asyncio.create_subprocess_exec(
                "sudo", str(self.CONSUMER_PATH), self.map_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._running = True
            return True
        except Exception:
            return False
    
    async def stop(self) -> None:
        """Stop the ring buffer consumer process."""
        self._running = False
        if self._process:
            try:
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                self._process.kill()
            except Exception:
                pass
            self._process = None
    
    async def read_events(self) -> AsyncIterator[PolicyEvent]:
        """Async iterator that yields events from the ring buffer."""
        if not self._process or not self._process.stdout:
            return
        
        while self._running:
            try:
                line = await asyncio.wait_for(
                    self._process.stdout.readline(),
                    timeout=0.1
                )
                if not line:
                    break
                
                event = self._parse_json_event(line.decode().strip())
                if event:
                    # Store event
                    self._events.append(event)
                    if len(self._events) > self._max_events:
                        self._events.pop(0)
                    
                    # Call callbacks
                    for callback in self._callbacks:
                        try:
                            callback(event)
                        except Exception:
                            pass
                    
                    yield event
                    
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break


class RingBufferReader:
    """Reads events from BPF ring buffer using perf/mmap.
    
    This is a simpler polling-based approach that works without BCC.
    Uses bpftool for map inspection.
    """
    
    def __init__(self):
        self.events: List[PolicyEvent] = []
        self._callbacks: List[Callable[[PolicyEvent], None]] = []
    
    def add_callback(self, callback: Callable[[PolicyEvent], None]) -> None:
        """Register a callback for new events."""
        self._callbacks.append(callback)
    
    def poll_events_from_trace(self) -> List[PolicyEvent]:
        """Poll for new events by parsing bpftool output.
        
        Note: This is a fallback. For real-time streaming, 
        use BCC or libbpf with proper ring buffer polling.
        """
        # For now, we'll integrate with the existing trace_pipe
        # and later add proper ring buffer polling
        return []
    
    def get_map_id(self, map_name: str = "policy_events") -> Optional[int]:
        """Get the map ID for the policy_events ring buffer."""
        try:
            result = subprocess.run(
                ["bpftool", "map", "list"],
                capture_output=True,
                text=True
            )
            
            for line in result.stdout.split('\n'):
                if map_name in line and "ringbuf" in line:
                    # Format: "123: ringbuf  name policy_events ..."
                    parts = line.split(':')
                    if parts:
                        return int(parts[0].strip())
            return None
        except Exception:
            return None


# Try to use BCC for proper ring buffer consumption
try:
    from bcc import BPF
    HAS_BCC = True
except ImportError:
    HAS_BCC = False


class BCCRingBufferConsumer:
    """Ring buffer consumer using BCC (if available).
    
    This provides proper kernel-to-userspace ring buffer streaming.
    """
    
    def __init__(self):
        if not HAS_BCC:
            raise ImportError("BCC not available. Install with: pip install bcc")
        
        self.events: List[PolicyEvent] = []
        self._callbacks: List[Callable[[PolicyEvent], None]] = []
        self._bpf = None
        self._running = False
    
    def add_callback(self, callback: Callable[[PolicyEvent], None]) -> None:
        """Register a callback for new events."""
        self._callbacks.append(callback)
    
    def _handle_event(self, cpu, data, size):
        """Handle a ring buffer event from BCC."""
        event = parse_event(bytes(data)[:size])
        if event:
            self.events.append(event)
            if len(self.events) > 1000:
                self.events.pop(0)
            
            for callback in self._callbacks:
                try:
                    callback(event)
                except Exception:
                    pass
    
    def attach_to_existing_map(self, map_path: str = "/sys/fs/bpf/policy_events") -> bool:
        """Attach to an existing pinned ring buffer map.
        
        Note: BCC doesn't directly support attaching to existing maps.
        We need to use a different approach with libbpf or perf.
        """
        # For BCC, we'd need to load a minimal BPF program that shares the map
        # This is complex - for now, return False to use alternative method
        return False


def create_consumer() -> RingBufferReader:
    """Create the best available ring buffer consumer."""
    return RingBufferReader()


# Simple test
if __name__ == "__main__":
    reader = RingBufferReader()
    map_id = reader.get_map_id()
    print(f"policy_events map ID: {map_id}")
    
    # Test event parsing
    test_data = struct.pack(
        '<IIIIIII B B xx',  # 7xu32 + 2xu8 + 2 bytes padding
        0x1400000a,  # src_ip: 10.0.0.20
        12345,       # src_port
        0x0a00000a,  # dest_ip: 10.0.0.10
        8080,        # dest_port
        6,           # protocol: TCP
        1,           # verdict: ALLOW
        100,         # packet_size
        0,           # is_egress: False
        2,           # tier: NETWORK_POLICY
    )
    
    event = parse_event(test_data)
    if event:
        print(f"Parsed test event: {event}")
