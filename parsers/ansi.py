"""Shared ANSI escape code handling for all parsers."""
import re

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
