"""Pure Python ring buffer consumer using libbpf via ctypes.

This eliminates the need for a separate C executable by calling libbpf
functions directly from Python.

Usage:
    consumer = LibbpfRingBufferConsumer("/sys/fs/bpf/policy_events")
    consumer.add_callback(lambda event: print(event))
    
    # Blocking poll loop
    while True:
        consumer.poll(timeout_ms=100)
    
    # Or async
    async for event in consumer.async_poll():
        print(event)
"""

import ctypes
import asyncio
import struct
import socket
import os
from dataclasses import dataclass
from typing import Optional, Callable, List, AsyncIterator
from pathlib import Path
from enum import IntEnum
from concurrent.futures import ThreadPoolExecutor


# Load libbpf
try:
    libbpf = ctypes.CDLL("libbpf.so.1")
except OSError:
    try:
        libbpf = ctypes.CDLL("libbpf.so")
    except OSError:
        libbpf = None


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
    protocol: int
    verdict: Verdict
    packet_size: int
    is_egress: bool
    tier: Tier
    runtime_ns: int = 0
    
    @property
    def protocol_name(self) -> str:
        protocols = {6: "TCP", 17: "UDP", 132: "SCTP", 1: "ICMP"}
        return protocols.get(self.protocol, str(self.protocol))
    
    @property
    def verdict_str(self) -> str:
        return "ALLOW" if self.verdict == Verdict.ALLOW else "DENY"
    
    @property
    def direction(self) -> str:
        return "EGRESS" if self.is_egress else "INGRESS"
    
    @property
    def runtime_us(self) -> float:
        return self.runtime_ns / 1000.0
    
    @property
    def tier_name(self) -> str:
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
    return socket.inet_ntoa(struct.pack('<I', ip_int))


def parse_event_bytes(data: bytes) -> Optional[PolicyEvent]:
    """Parse raw event bytes into PolicyEvent.
    
    struct data_t layout (36 bytes):
        u32 src_ip       (0-3)
        u32 src_port     (4-7)
        u32 dest_ip      (8-11)
        u32 dest_port    (12-15)
        u32 protocol     (16-19)
        u32 verdict      (20-23)
        u32 packet_sz    (24-27)
        u32 runtime_ns   (28-31)
        u8  is_egress    (32)
        u8  tier         (33)
        u8  padding[2]   (34-35)
    """
    if len(data) < 34:
        return None
    
    try:
        # Unpack: 8 x u32, 2 x u8
        fields = struct.unpack('<IIIIIIII BB', data[:34])
        
        return PolicyEvent(
            src_ip=ip_to_str(fields[0]),
            src_port=fields[1],
            dest_ip=ip_to_str(fields[2]),
            dest_port=fields[3],
            protocol=fields[4],
            verdict=Verdict(fields[5]),
            packet_size=fields[6],
            runtime_ns=fields[7],
            is_egress=bool(fields[8]),
            tier=Tier(fields[9]),
        )
    except Exception:
        return None


# C function types for libbpf
if libbpf:
    # typedef int (*ring_buffer_sample_fn)(void *ctx, void *data, size_t size);
    RING_BUFFER_SAMPLE_FN = ctypes.CFUNCTYPE(
        ctypes.c_int,           # return type
        ctypes.c_void_p,        # ctx
        ctypes.c_void_p,        # data
        ctypes.c_size_t         # size
    )
    
    # int bpf_obj_get(const char *pathname);
    libbpf.bpf_obj_get.argtypes = [ctypes.c_char_p]
    libbpf.bpf_obj_get.restype = ctypes.c_int
    
    # struct ring_buffer *ring_buffer__new(int map_fd, ring_buffer_sample_fn sample_cb,
    #                                       void *ctx, const struct ring_buffer_opts *opts);
    libbpf.ring_buffer__new.argtypes = [
        ctypes.c_int,           # map_fd
        RING_BUFFER_SAMPLE_FN,  # sample_cb
        ctypes.c_void_p,        # ctx
        ctypes.c_void_p         # opts (NULL for defaults)
    ]
    libbpf.ring_buffer__new.restype = ctypes.c_void_p
    
    # int ring_buffer__poll(struct ring_buffer *rb, int timeout_ms);
    libbpf.ring_buffer__poll.argtypes = [ctypes.c_void_p, ctypes.c_int]
    libbpf.ring_buffer__poll.restype = ctypes.c_int
    
    # void ring_buffer__free(struct ring_buffer *rb);
    libbpf.ring_buffer__free.argtypes = [ctypes.c_void_p]
    libbpf.ring_buffer__free.restype = None


class LibbpfRingBufferConsumer:
    """Ring buffer consumer using libbpf via ctypes.
    
    This is a pure Python implementation that calls libbpf functions directly.
    """
    
    def __init__(self, map_path: str = "/sys/fs/bpf/policy_events"):
        if not libbpf:
            raise RuntimeError("libbpf not available")
        
        self.map_path = map_path
        self._rb = None
        self._map_fd = -1
        self._callbacks: List[Callable[[PolicyEvent], None]] = []
        self._events: List[PolicyEvent] = []
        self._max_events = 1000
        self._running = False
        
        # Keep reference to callback to prevent garbage collection
        self._sample_cb = RING_BUFFER_SAMPLE_FN(self._handle_sample)
    
    def _handle_sample(self, ctx: int, data: int, size: int) -> int:
        """Handle a sample from the ring buffer.
        
        This is called by libbpf for each event in the ring buffer.
        """
        try:
            # Read the raw bytes from the data pointer
            raw_data = ctypes.string_at(data, size)
            event = parse_event_bytes(raw_data)
            
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
        except Exception:
            pass
        
        return 0  # Return 0 to continue processing
    
    def open(self) -> bool:
        """Open the ring buffer map and set up polling."""
        if not os.path.exists(self.map_path):
            return False
        
        # Get fd for the pinned map
        self._map_fd = libbpf.bpf_obj_get(self.map_path.encode())
        if self._map_fd < 0:
            return False
        
        # Create ring buffer
        self._rb = libbpf.ring_buffer__new(
            self._map_fd,
            self._sample_cb,
            None,  # ctx
            None   # opts
        )
        
        if not self._rb:
            os.close(self._map_fd)
            self._map_fd = -1
            return False
        
        self._running = True
        return True
    
    def close(self) -> None:
        """Close the ring buffer and release resources."""
        self._running = False
        
        if self._rb:
            libbpf.ring_buffer__free(self._rb)
            self._rb = None
        
        if self._map_fd >= 0:
            os.close(self._map_fd)
            self._map_fd = -1
    
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
    
    def poll(self, timeout_ms: int = 100) -> int:
        """Poll the ring buffer for events.
        
        Args:
            timeout_ms: Timeout in milliseconds (0 = non-blocking, -1 = infinite)
        
        Returns:
            Number of events consumed, or negative on error.
        """
        if not self._rb:
            return -1
        
        return libbpf.ring_buffer__poll(self._rb, timeout_ms)
    
    async def async_poll(
        self, 
        timeout_ms: int = 100,
        poll_interval: float = 0.01
    ) -> AsyncIterator[PolicyEvent]:
        """Async iterator that yields events from the ring buffer.
        
        Uses a thread pool to avoid blocking the event loop during polling.
        """
        executor = ThreadPoolExecutor(max_workers=1)
        loop = asyncio.get_event_loop()
        
        event_queue: List[PolicyEvent] = []
        
        def capture_callback(event: PolicyEvent) -> None:
            event_queue.append(event)
        
        self.add_callback(capture_callback)
        
        try:
            while self._running:
                # Poll in thread pool to avoid blocking
                await loop.run_in_executor(executor, self.poll, timeout_ms)
                
                # Yield any captured events
                while event_queue:
                    yield event_queue.pop(0)
                
                # Small sleep to prevent tight loop
                await asyncio.sleep(poll_interval)
        finally:
            self.remove_callback(capture_callback)
            executor.shutdown(wait=False)
    
    def __enter__(self):
        self.open()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


class AsyncLibbpfRingBufferConsumer:
    """Async-friendly wrapper around LibbpfRingBufferConsumer.
    
    Provides the same interface as AsyncRingBufferConsumer but uses
    libbpf directly instead of spawning a C subprocess.
    """
    
    def __init__(self, map_path: str = "/sys/fs/bpf/policy_events"):
        self.map_path = map_path
        self._consumer: Optional[LibbpfRingBufferConsumer] = None
        self._running = False
        self._callbacks: List[Callable[[PolicyEvent], None]] = []
        self._events: List[PolicyEvent] = []
        self._max_events = 1000
        self._executor = ThreadPoolExecutor(max_workers=1)
    
    @property
    def consumer_exists(self) -> bool:
        """Check if libbpf is available (compatibility with C consumer interface)."""
        return libbpf is not None
    
    @property
    def map_exists(self) -> bool:
        """Check if the ring buffer map exists."""
        return os.path.exists(self.map_path)
    
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
    
    async def start(self) -> bool:
        """Start the ring buffer consumer."""
        import sys
        print(f"[ringbuf] start() called, libbpf={libbpf is not None}, map_exists={self.map_exists}", file=sys.stderr)
        
        if not libbpf or not self.map_exists:
            print(f"[ringbuf] returning False - libbpf or map missing", file=sys.stderr)
            return False
        
        try:
            self._consumer = LibbpfRingBufferConsumer(self.map_path)
            print(f"[ringbuf] created consumer, calling open()...", file=sys.stderr)
            
            if not self._consumer.open():
                print(f"[ringbuf] open() failed", file=sys.stderr)
                return False
            
            print(f"[ringbuf] open() succeeded, fd={self._consumer._map_fd}", file=sys.stderr)
            self._running = True
            return True
        except Exception as e:
            print(f"[ringbuf] exception: {e}", file=sys.stderr)
            return False
    
    async def stop(self) -> None:
        """Stop the ring buffer consumer."""
        self._running = False
        if self._consumer:
            self._consumer.close()
            self._consumer = None
        self._executor.shutdown(wait=False)
    
    async def read_events(self) -> AsyncIterator[PolicyEvent]:
        """Async iterator that yields events from the ring buffer."""
        if not self._consumer:
            return
        
        event_queue: List[PolicyEvent] = []
        
        def capture_event(event: PolicyEvent) -> None:
            # Store in our list
            self._events.append(event)
            if len(self._events) > self._max_events:
                self._events.pop(0)
            
            # Add to yield queue
            event_queue.append(event)
            
            # Call external callbacks
            for callback in self._callbacks:
                try:
                    callback(event)
                except Exception:
                    pass
        
        # Add callback before polling
        self._consumer.add_callback(capture_event)
        
        loop = asyncio.get_event_loop()
        
        try:
            while self._running and self._consumer:
                # Poll in executor to avoid blocking
                try:
                    await asyncio.wait_for(
                        loop.run_in_executor(
                            self._executor, 
                            self._consumer.poll, 
                            100
                        ),
                        timeout=0.2
                    )
                except asyncio.TimeoutError:
                    pass
                
                # Yield captured events
                while event_queue:
                    yield event_queue.pop(0)
                
        except asyncio.CancelledError:
            pass
        finally:
            if self._consumer:
                self._consumer.remove_callback(capture_event)


# Test when run directly
if __name__ == "__main__":
    import sys
    
    if not libbpf:
        print("libbpf not available!")
        sys.exit(1)
    
    map_path = sys.argv[1] if len(sys.argv) > 1 else "/sys/fs/bpf/policy_events"
    
    print(f"Opening ring buffer at {map_path}...")
    
    consumer = LibbpfRingBufferConsumer(map_path)
    consumer.add_callback(lambda e: print(e))
    
    if not consumer.open():
        print(f"Failed to open ring buffer at {map_path}")
        print("Make sure the BPF program is loaded and the map is pinned.")
        sys.exit(1)
    
    print("Polling for events... (Ctrl+C to stop)")
    
    try:
        while True:
            consumer.poll(timeout_ms=1000)
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        consumer.close()
