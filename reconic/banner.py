"""Startup banner: block lettering in the terminal's own colours, with plain fallbacks."""
from __future__ import annotations

import os
import shutil
import sys

from . import __version__

_BANNER_GLYPHS = {
    'R': ("██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"),
    'E': ("███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"),
    'C': (" ██████╗", "██╔════╝", "██║     ", "██║     ", "╚██████╗", " ╚═════╝"),
    'O': (" ██████╗ ", "██╔═══██╗", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "),
    'N': ("███╗   ██╗", "████╗  ██║", "██╔██╗ ██║", "██║╚██╗██║", "██║ ╚████║", "╚═╝  ╚═══╝"),
    'I': ("██╗", "██║", "██║", "██║", "██║", "╚═╝"),
}
_BANNER_TAGLINE = "Automated Reconnaissance Framework"
_BANNER_PIPELINE = ("subfinder", "httpx", "katana", "nuclei")
_BANNER_AUTHOR = "by Othman Kamal"

# Standard ANSI attributes only, so the banner follows the user's terminal theme.
_RESET, _BOLD, _DIM, _ACCENT = "\033[0m", "\033[1m", "\033[2m", "\033[36m"


def banner_art() -> list:
    return [''.join(_BANNER_GLYPHS[ch][row] for ch in 'RECONIC') for row in range(6)]


def render_banner(color: bool = True, unicode_ok: bool = True, width: int = 80) -> str:
    """Build the banner; falls back to one plain line when the terminal can't show the art"""
    art = banner_art()
    art_width = len(art[0])
    version = f"v{__version__}"

    if not unicode_ok or width < art_width + 2:
        return f"RECONIC {version} - {_BANNER_TAGLINE} - {_BANNER_AUTHOR}\n"

    reset, bold, dim, accent = (_RESET, _BOLD, _DIM, _ACCENT) if color else ("", "", "", "")
    out = [""]

    for line in art:
        line = line.rstrip()
        if not color:
            out.append(" " + line)
            continue
        # Solid blocks in the default foreground, box-drawing edges dimmed as a shadow.
        cells, solid = [], None
        for ch in line:
            is_solid = ch == '█'
            if ch != ' ' and is_solid != solid:
                cells.append(reset + (bold if is_solid else dim))
                solid = is_solid
            cells.append(ch)
        out.append(" " + ''.join(cells) + reset)

    pipeline_plain = " ▸ ".join(_BANNER_PIPELINE)
    pipeline = f" {dim}▸{reset} ".join(_BANNER_PIPELINE)

    out.append("")
    out.append(f" {bold}{_BANNER_TAGLINE}{reset}"
               f"{' ' * (art_width - len(_BANNER_TAGLINE) - len(version))}{accent}{version}{reset}")
    out.append(f" {pipeline}"
               f"{' ' * (art_width - len(pipeline_plain) - len(_BANNER_AUTHOR))}{dim}{_BANNER_AUTHOR}{reset}")
    out.append(f" {dim}{'─' * art_width}{reset}")
    return '\n'.join(out) + '\n'


def print_banner(stream=None) -> None:
    """Print the banner to stderr so piped stdout stays clean"""
    stream = stream or sys.stderr
    tty = stream.isatty()
    encoding = (getattr(stream, 'encoding', None) or '').lower().replace('-', '')
    stream.write(render_banner(
        color=tty and 'NO_COLOR' not in os.environ and os.environ.get('TERM') != 'dumb',
        unicode_ok=tty and encoding.startswith('utf'),
        width=shutil.get_terminal_size((80, 24)).columns,
    ))
    stream.flush()
