"""Read the real stylesheet and compute colour facts about it.

Not a test module: the helpers here are imported by the tests that assert the
UI shell's accessibility contract (``test_ui_shell.py``) and the chip-
distinctness contract (``test_trust_corroboration.py``).

Everything is derived from ``src/ccf/api/static/css/app.css`` itself. Nothing
here carries a copy of a colour: a test that compares a fixture against the
fixture's own string proves nothing, and this programme has shipped that bug
before. The parser resolves ``var()`` chains and alpha compositing the way a
browser does, so the numbers reported are the numbers a user sees.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
CSS_PATH = _REPO / "src" / "ccf" / "api" / "static" / "css" / "app.css"

LIGHT = "light"
DARK = "dark"
THEMES = (LIGHT, DARK)

#: WCAG 2.1 AA.
AA_BODY = 4.5
AA_LARGE = 3.0
#: Non-text contrast (1.4.11) for a boundary that has to be perceivable.
AA_UI = 3.0


# ── CSS parsing ──────────────────────────────────────────────────────────────


def _block(css: str, selector: str) -> str:
    """Return the declaration body of the first rule matching ``selector``."""
    i = css.index(selector)
    j = css.index("{", i)
    depth = 0
    for k in range(j, len(css)):
        if css[k] == "{":
            depth += 1
        elif css[k] == "}":
            depth -= 1
            if depth == 0:
                return css[j + 1 : k]
    raise AssertionError(f"unterminated rule for {selector!r}")


def _declarations(body: str) -> dict[str, str]:
    return {
        m.group(1): m.group(2).strip()
        for m in re.finditer(r"(--[a-z0-9-]+)\s*:\s*([^;]+);", body)
    }


def read_css() -> str:
    """The stylesheet with comments removed — comments otherwise glue
    themselves to the next selector and silently hide a rule from the parser."""
    return re.sub(r"/\*.*?\*/", "", CSS_PATH.read_text(encoding="utf-8"), flags=re.S)


def root_tokens(css: str | None = None) -> dict[str, str]:
    return _declarations(_block(css or read_css(), ":root {"))


def dark_tokens(css: str | None = None) -> dict[str, str]:
    return _declarations(_block(css or read_css(), 'html[data-theme="dark"] {'))


def tokens_for(theme: str, css: str | None = None) -> dict[str, str]:
    css = css or read_css()
    merged = dict(root_tokens(css))
    if theme == DARK:
        merged.update(dark_tokens(css))
    return merged


# ── colour ───────────────────────────────────────────────────────────────────

RGBA = tuple[float, float, float, float]


def parse_color(value: str, tokens: dict[str, str], _depth: int = 0) -> RGBA:
    """Resolve a CSS colour to straight RGBA in 0-255 / 0-1, following var()."""
    if _depth > 12:
        raise AssertionError(f"var() cycle resolving {value!r}")
    v = value.strip()
    m = re.fullmatch(r"var\(\s*(--[a-z0-9-]+)\s*(?:,\s*(.+))?\)", v, re.I)
    if m:
        name = m.group(1)
        if name in tokens:
            return parse_color(tokens[name], tokens, _depth + 1)
        if m.group(2):
            return parse_color(m.group(2), tokens, _depth + 1)
        raise AssertionError(f"undefined token {name}")
    m = re.fullmatch(r"#([0-9a-f]{3,8})", v, re.I)
    if m:
        h = m.group(1)
        if len(h) in (3, 4):
            h = "".join(c * 2 for c in h)
        r, g, b = (int(h[i : i + 2], 16) for i in (0, 2, 4))
        a = int(h[6:8], 16) / 255 if len(h) == 8 else 1.0
        return (float(r), float(g), float(b), a)
    m = re.fullmatch(r"rgba?\(([^)]+)\)", v, re.I)
    if m:
        parts = [p.strip() for p in re.split(r"[,/]", m.group(1)) if p.strip()]
        nums = [float(p.rstrip("%")) for p in parts]
        r, g, b = nums[0], nums[1], nums[2]
        a = nums[3] if len(nums) > 3 else 1.0
        return (r, g, b, a)
    if v == "transparent":
        return (0.0, 0.0, 0.0, 0.0)
    raise AssertionError(f"cannot parse colour {value!r}")


def composite(fg: RGBA, bg: RGBA) -> RGBA:
    """Source-over: place ``fg`` on an opaque ``bg``."""
    a = fg[3]
    return (
        fg[0] * a + bg[0] * (1 - a),
        fg[1] * a + bg[1] * (1 - a),
        fg[2] * a + bg[2] * (1 - a),
        1.0,
    )


def _linear(c: float) -> float:
    c = c / 255.0
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def luminance(c: RGBA) -> float:
    r, g, b = (_linear(x) for x in c[:3])
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(fg: RGBA, bg: RGBA) -> float:
    """WCAG 2.1 contrast ratio. ``fg`` is composited onto ``bg`` if translucent."""
    solid = composite(fg, bg) if fg[3] < 1 else fg
    a, b = luminance(solid), luminance(bg)
    hi, lo = max(a, b), min(a, b)
    return (hi + 0.05) / (lo + 0.05)


def hexed(c: RGBA) -> str:
    return "#" + "".join(f"{max(0, min(255, round(x))):02x}" for x in c[:3])


# ── perceptual distance (CIEDE2000) ──────────────────────────────────────────


def _to_lab(c: RGBA) -> tuple[float, float, float]:
    r, g, b = (_linear(x) for x in c[:3])
    x = (0.4124564 * r + 0.3575761 * g + 0.1804375 * b) / 0.95047
    y = 0.2126729 * r + 0.7151522 * g + 0.0721750 * b
    z = (0.0193339 * r + 0.1191920 * g + 0.9503041 * b) / 1.08883

    def f(t: float) -> float:
        return t ** (1 / 3) if t > 216 / 24389 else (24389 / 27 * t + 16) / 116

    fx, fy, fz = f(x), f(y), f(z)
    return (116 * fy - 16, 500 * (fx - fy), 200 * (fy - fz))


def delta_e(c1: RGBA, c2: RGBA) -> float:
    """CIEDE2000. ~1.0 is the just-noticeable difference for adjacent patches."""
    l1, a1, b1 = _to_lab(c1)
    l2, a2, b2 = _to_lab(c2)
    avg_l = (l1 + l2) / 2
    c1s, c2s = math.hypot(a1, b1), math.hypot(a2, b2)
    avg_c = (c1s + c2s) / 2
    g = 0.5 * (1 - math.sqrt(avg_c**7 / (avg_c**7 + 25**7))) if avg_c else 0.0
    a1p, a2p = (1 + g) * a1, (1 + g) * a2
    c1p, c2p = math.hypot(a1p, b1), math.hypot(a2p, b2)
    avg_cp = (c1p + c2p) / 2
    h1p = math.degrees(math.atan2(b1, a1p)) % 360 if (a1p or b1) else 0.0
    h2p = math.degrees(math.atan2(b2, a2p)) % 360 if (a2p or b2) else 0.0
    dlp = l2 - l1
    dcp = c2p - c1p
    if c1p * c2p == 0:
        dhp = 0.0
    elif abs(h2p - h1p) <= 180:
        dhp = h2p - h1p
    else:
        dhp = h2p - h1p - 360 if h2p > h1p else h2p - h1p + 360
    dhp_big = 2 * math.sqrt(c1p * c2p) * math.sin(math.radians(dhp) / 2)
    if c1p * c2p == 0:
        avg_hp = h1p + h2p
    elif abs(h1p - h2p) <= 180:
        avg_hp = (h1p + h2p) / 2
    elif h1p + h2p < 360:
        avg_hp = (h1p + h2p + 360) / 2
    else:
        avg_hp = (h1p + h2p - 360) / 2
    t = (
        1
        - 0.17 * math.cos(math.radians(avg_hp - 30))
        + 0.24 * math.cos(math.radians(2 * avg_hp))
        + 0.32 * math.cos(math.radians(3 * avg_hp + 6))
        - 0.20 * math.cos(math.radians(4 * avg_hp - 63))
    )
    sl = 1 + (0.015 * (avg_l - 50) ** 2) / math.sqrt(20 + (avg_l - 50) ** 2)
    sc = 1 + 0.045 * avg_cp
    sh = 1 + 0.015 * avg_cp * t
    rt = (
        -2
        * math.sqrt(avg_cp**7 / (avg_cp**7 + 25**7))
        * math.sin(math.radians(60 * math.exp(-(((avg_hp - 275) / 25) ** 2))))
        if avg_cp
        else 0.0
    )
    return math.sqrt(
        (dlp / sl) ** 2
        + (dcp / sc) ** 2
        + (dhp_big / sh) ** 2
        + rt * (dcp / sc) * (dhp_big / sh)
    )


# ── the chip vocabulary, read from the stylesheet ────────────────────────────

#: The six semantic variants §2 of the spec names, plus the unsuffixed base
#: chip they all share a shape with. All seven are rendered by the same six
#: vocabularies (Trust Center, guided onboarding, portal grants, two assessment
#: vocabularies), so all seven have to stay apart from one another.
CHIP_CLASSES = (
    "chip",
    "chip--brand",
    "chip--ok",
    "chip--warn",
    "chip--err",
    "chip--info",
    "chip--ghost",
)


@dataclass(frozen=True)
class ChipPaint:
    """What a chip actually looks like once the cascade and alpha have run."""

    name: str
    theme: str
    background: RGBA
    text: RGBA
    border: RGBA

    @property
    def text_contrast(self) -> float:
        return contrast(self.text, self.background)

    @property
    def border_contrast(self) -> float:
        return contrast(self.border, self.background)


def _rule_bodies(css: str, selector: str) -> list[str]:
    """Every declaration body whose selector list contains ``selector`` exactly.

    Exactly, not by suffix: ``html[data-theme="dark"] .chip--ok`` ends with
    ``.chip--ok``, and folding it into the light theme made every light chip
    report the dark theme's text colour. The caller names the full selector it
    wants, in cascade order.
    """
    out = []
    for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", css):
        sels = [re.sub(r"\s+", " ", s).strip() for s in m.group(1).split(",")]
        if selector in sels:
            out.append(m.group(2))
    return out


def _prop(bodies: list[str], prop: str) -> str | None:
    found = None
    for body in bodies:
        for m in re.finditer(rf"(?:^|;)\s*{prop}\s*:\s*([^;]+)", body):
            found = m.group(1).strip()
    return found


def chip_paint(theme: str, css: str | None = None) -> dict[str, ChipPaint]:
    """Resolve every chip variant to the colours it paints, per theme.

    A chip sits on a card, so translucent tints are composited over
    ``--bg-elevated`` — the surface 24 of the 54 pages put chips on.
    """
    css = css or read_css()
    tokens = tokens_for(theme, css)
    surface = parse_color(tokens["--bg-elevated"], tokens)
    prefix = 'html[data-theme="dark"] ' if theme == DARK else ""

    out: dict[str, ChipPaint] = {}
    for name in CHIP_CLASSES:
        # Cascade order: base chip, base chip's dark override, the variant,
        # the variant's dark override. Later wins, which is what _prop takes.
        selectors = [".chip"]
        if theme == DARK:
            selectors.append(f"{prefix}.chip")
        if name != "chip":
            selectors.append(f".{name}")
            if theme == DARK:
                selectors.append(f"{prefix}.{name}")
        bodies = [b for sel in selectors for b in _rule_bodies(css, sel)]
        bg_decl = _prop(bodies, "background")
        fg_decl = _prop(bodies, "color")
        border_decl = _prop(bodies, "border-color") or "transparent"
        assert bg_decl and fg_decl, f"{name}: no background/color in the stylesheet"
        bg = composite(parse_color(bg_decl, tokens), surface)
        fg = composite(parse_color(fg_decl, tokens), bg)
        border = composite(parse_color(border_decl, tokens), bg)
        out[name] = ChipPaint(name=name, theme=theme, background=bg, text=fg, border=border)
    return out
