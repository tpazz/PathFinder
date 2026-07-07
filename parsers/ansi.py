"""Shared ANSI handling for all of PathFinder: escape stripping + colour output."""
import re
import sys

# Comprehensive pattern covering:
# - CSI sequences: \x1b[...X  (colors, cursor, erase - all terminal variants)
# - OSC sequences: \x1b]...BEL/ST  (window title, etc.)
# - Character set: \x1b(X, \x1b)X
# - Simple escapes: \x1b followed by single character
# - 8-bit CSI: \x9b...X
ANSI_ESCAPE_PATTERN = re.compile(
    r'\x1b'
    r'(?:'
    r'\[[0-9;]*[a-zA-Z]'   # CSI sequences (SGR colors, cursor, erase, etc.)
    r'|\[[0-9;]*m'         # Explicit SGR (redundant but safe)
    r'|\].*?(?:\x07|\x1b\\)'  # OSC sequences terminated by BEL or ST
    r'|\([A-Za-z0]'        # Character set selection
    r'|[=>NOM78DHE]'       # Simple single-char escapes (cursor save, etc.)
    r')'
    r'|\x9b[0-9;]*[a-zA-Z]'  # 8-bit CSI (rare, but used by some terminals)
)

# Raw SGR codes used across PathFinder's CLI output.
_CODES = {
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "LIGHT_BLUE": "\033[94m",
    "CYAN": "\033[96m",
    "BOLD": "\033[1m",
    "END": "\033[0m",
}


class _Colors:
    """Holds colour codes that collapse to empty strings when colour is disabled.

    Code references attributes directly (e.g. ``C.RED``); calling
    :func:`set_color_enabled` swaps every attribute between the real escape
    code and ``""`` so existing f-strings keep working with no other changes.
    """

    def __init__(self, enabled=True):
        self.enable(enabled)

    def enable(self, enabled):
        self.enabled = enabled
        for name, code in _CODES.items():
            setattr(self, name, code if enabled else "")


# Default to TTY-aware: colour on only when stdout is an interactive terminal.
# This delivers the "no escape codes when piped/redirected" behaviour for free.
C = _Colors(enabled=sys.stdout.isatty())


def set_color_enabled(enabled):
    """Force colour output on or off (e.g. from a --no-color flag)."""
    C.enable(enabled)


def should_enable_color(no_color_flag=False):
    """Resolve whether colour should be on: never when --no-color, else TTY-aware."""
    if no_color_flag:
        return False
    return sys.stdout.isatty()


def warn(message):
    """Print a '[!]'-style warning/error line in bold yellow.

    Shared by the parsers so every '[!]' line is styled consistently with the
    rest of PathFinder (colour collapses to plain text when disabled).
    """
    print(f"{C.BOLD}{C.YELLOW}{message}{C.END}")
