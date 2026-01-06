"""Main entry point for ebpf_manager package."""

from .tui import run_tui

def main():
    """Entry point - run TUI."""
    run_tui()

if __name__ == "__main__":
    main()
