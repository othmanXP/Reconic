"""Startup banner: gradient block lettering with plain fallbacks."""
from __future__ import annotations

import os
import shutil
import sys
from typing import Tuple

from . import __version__

_BANNER_GLYPHS = {
    'R': ("██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"),
    'E': ("███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"),
    'C': (" ██████╗", "██╔════╝", "██║     ", "██║     ", "╚██████╗", " ╚═════╝"),
    'O': (" ██████╗ ", "██╔═══██╗", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "),
    'N': ("███╗   ██╗", "████╗  ██║", "██╔██╗ ██║", "██║╚██╗██║", "██║ ╚████║", "╚═╝  ╚═══╝"),
    'I': ("██╗", "██║", "██║", "██║", "██║", "╚═╝"),
}
# Diagonal gradient: cyan -> violet -> pink
_BANNER_STOPS = ((34, 211, 238), (167, 139, 250), (244, 114, 182))
_BANNER_TAGLINE = "Automated Reconnaissance Framework"
_BANNER_PIPELINE = ("subfinder", "httpx", "katana", "nuclei")
_BANNER_AUTHOR = "by Othman Kamal"


def _banner_gradient(t: float) -> Tuple[int, int, int]:
    """Colour at position t (0..1) along the banner gradient"""
    t = min(max(t, 0.0), 1.0) * (len(_BANNER_STOPS) - 1)
    i = min(int(t), len(_BANNER_STOPS) - 2)
    a, b, f = _BANNER_STOPS[i], _BANNER_STOPS[i + 1], t - i
    return tuple(round(a[k] + (b[k] - a[k]) * f) for k in range(3))


def _banner_paint(rgb: Tuple[int, int, int], truecolor: bool) -> str:
    """ANSI foreground escape for rgb, in 24-bit or the 256-colour cube"""
    if truecolor:
        return f"\033[38;2;{rgb[0]};{rgb[1]};{rgb[2]}m"
    r, g, b = (round(c / 255 * 5) for c in rgb)
    return f"\033[38;5;{16 + 36 * r + 6 * g + b}m"


def render_banner(color: bool = True, truecolor: bool = True, unicode_ok: bool = True, width: int = 80) -> str:
    """Build the banner; falls back to one plain line when the terminal can't show the art"""
    art = [''.join(_BANNER_GLYPHS[ch][row] for ch in 'RECONIC') for row in range(6)]
    art_width = len(art[0])
    version = f"v{__version__}"

    if not unicode_ok or width < art_width + 2:
        return f"RECONIC {version} - {_BANNER_TAGLINE} - {_BANNER_AUTHOR}\n"

    reset = "\033[0m" if color else ""
    dim = "\033[2m" if color else ""
    bold = "\033[1m" if color else ""
    out = [""]

    for row, line in enumerate(art):
        if not color:
            out.append(" " + line.rstrip())
            continue
        cells = []
        for col, ch in enumerate(line):
            if ch == ' ':
                cells.append(ch)
                continue
            rgb = _banner_gradient((col + row * 3) / (art_width + 15))
            if ch != '█':  # box-drawing edges form the shadow: same hue, darker
                rgb = tuple(round(c * 0.45) for c in rgb)
            cells.append(_banner_paint(rgb, truecolor) + ch)
        out.append(" " + ''.join(cells).rstrip() + reset)

    def accent(t: float) -> str:
        return _banner_paint(_banner_gradient(t), truecolor) if color else ""

    pipeline_plain = " ▸ ".join(_BANNER_PIPELINE)
    pipeline = f" {dim}▸{reset} ".join(
        f"{accent(i / (len(_BANNER_PIPELINE) - 1))}{name}{reset}" for i, name in enumerate(_BANNER_PIPELINE)
    )

    out.append("")
    out.append(f" {bold}{_BANNER_TAGLINE}{reset}"
               f"{' ' * (art_width - len(_BANNER_TAGLINE) - len(version))}{accent(1.0)}{version}{reset}")
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
        truecolor=os.environ.get('COLORTERM', '').lower() in ('truecolor', '24bit'),
        unicode_ok=tty and encoding.startswith('utf'),
        width=shutil.get_terminal_size((80, 24)).columns,
    ))
    stream.flush()
