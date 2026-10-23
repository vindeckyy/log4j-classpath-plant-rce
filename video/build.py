#!/usr/bin/env python3
"""Render the POC video for the Log4j classpath-plant finding.

    python3 video/build.py                 # full video -> video/out/log4j-classpath-plant-poc.mp4
    python3 video/build.py --scene demo-rce --preview   # single scene -> PNG frames
    python3 video/build.py --no-audio      # video only

Footage is captured live from lab/ at build time, so what the video shows is what the
lab actually prints. Narration is synthesised with piper (see video/README.md).
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import sys
import wave
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, str(Path(__file__).resolve().parent))
from script import REPO, SCENES, SUBTITLE, TITLE  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "video" / "out"
TTS_DIR = OUT / "tts"
W, H, FPS = 1920, 1080, 30
CAPTION_TOP = 928
CONTENT_BOTTOM = 916
PIPER = Path.home() / ".venvs/piper/bin/python"
VOICE = Path.home() / ".local/share/piper-voices/en_US-lessac-medium.onnx"

# ----------------------------------------------------------------------------- palette
BG_TOP = (11, 14, 22)
BG_BOTTOM = (6, 8, 13)
SURFACE = (18, 23, 34)
SURFACE_2 = (23, 29, 42)
BORDER = (38, 47, 66)
TEXT = (232, 237, 245)
TEXT_2 = (172, 184, 205)
MUTED = (122, 134, 160)
ACCENT = (255, 77, 90)       # attacker / danger
ACCENT_DIM = (92, 33, 41)
CYAN = (79, 195, 247)
GREEN = (53, 208, 127)
AMBER = (255, 194, 75)
TERM_BG = (9, 12, 19)
TERM_CHROME = (21, 27, 38)

FONT_DIR_SANS = "/usr/share/fonts/opentype/inter"
FONT_DIR_MONO = "/usr/share/fonts/truetype/jetbrains-mono"

# ----------------------------------------------------------------------------- fonts
_FONTS: dict[tuple[str, int, int], ImageFont.FreeTypeFont] = {}


def font(kind: str, size: int, weight: int = 400) -> ImageFont.FreeTypeFont:
    key = (kind, size, weight)
    if key not in _FONTS:
        if kind == "mono":
            path = {
                400: f"{FONT_DIR_MONO}/JetBrainsMono-Regular.ttf",
                500: f"{FONT_DIR_MONO}/JetBrainsMono-Medium.ttf",
                700: f"{FONT_DIR_MONO}/JetBrainsMono-Bold.ttf",
            }[weight]
        else:
            path = {
                400: f"{FONT_DIR_SANS}/Inter-Regular.otf",
                500: f"{FONT_DIR_SANS}/Inter-Medium.otf",
                600: f"{FONT_DIR_SANS}/Inter-SemiBold.otf",
                700: f"{FONT_DIR_SANS}/Inter-Bold.otf",
                800: f"{FONT_DIR_SANS}/Inter-ExtraBold.otf",
                900: f"{FONT_DIR_SANS}/Inter-Black.otf",
            }[weight]
        _FONTS[key] = ImageFont.truetype(path, size)
    return _FONTS[key]


def vfont(size: int, weight: int = 400) -> ImageFont.FreeTypeFont:
    """Sans-serif alias used by the scene code."""
    return font("sans", size, weight)


# ----------------------------------------------------------------------------- helpers
def ease(t: float) -> float:
    t = max(0.0, min(1.0, t))
    return 1 - (1 - t) ** 3


def ramp(t: float, start: float, dur: float = 0.4) -> float:
    if t < start:
        return 0.0
    return ease((t - start) / dur)


def lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t


def text_width(draw: ImageDraw.ImageDraw, s: str, f: ImageFont.FreeTypeFont) -> float:
    return draw.textlength(s, font=f)


def wrap(draw: ImageDraw.ImageDraw, s: str, f: ImageFont.FreeTypeFont, max_w: float) -> list[str]:
    words, lines, cur = s.split(), [], ""
    for w in words:
        trial = f"{cur} {w}".strip()
        if text_width(draw, trial, f) <= max_w or not cur:
            cur = trial
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines


def rrect(draw: ImageDraw.ImageDraw, box, radius, fill=None, outline=None, width=1):
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)


def shadow(img: Image.Image, box, radius, blur=18, alpha=70) -> None:
    x0, y0, x1, y1 = box
    sh = Image.new("RGBA", img.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(sh)
    d.rounded_rectangle((x0 + 6, y0 + 10, x1 + 6, y1 + 12), radius=radius, fill=(0, 0, 0, alpha))
    sh = sh.filter(__import__("PIL.ImageFilter", fromlist=["ImageFilter"]).GaussianBlur(blur))
    img.alpha_composite(sh)


_bg_cache: dict[tuple, Image.Image] = {}


def background() -> Image.Image:
    key = ("bg", W, H)
    if key not in _bg_cache:
        base = Image.new("RGB", (W, H), BG_BOTTOM)
        grad = Image.new("RGB", (1, H))
        gd = ImageDraw.Draw(grad)
        for y in range(H):
            f = y / H
            gd.point((0, y), fill=tuple(int(lerp(BG_TOP[i], BG_BOTTOM[i], f ** 0.8)) for i in range(3)))
        base = grad.resize((W, H), Image.BILINEAR)
        glow = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        g = ImageDraw.Draw(glow)
        g.ellipse((-760, -980, 900, 120), fill=(255, 77, 90, 20))
        g.ellipse((1180, 380, 2560, 1460), fill=(79, 195, 247, 16))
        base = Image.alpha_composite(base.convert("RGBA"), glow)
        # faint grid
        grid = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        gd2 = ImageDraw.Draw(grid)
        for x in range(0, W, 60):
            gd2.line([(x, 0), (x, H)], fill=(255, 255, 255, 5), width=1)
        for y in range(0, H, 60):
            gd2.line([(0, y), (W, y)], fill=(255, 255, 255, 5), width=1)
        base = Image.alpha_composite(base, grid)
        _bg_cache[key] = base
    return _bg_cache[key].copy()


def chrome(img: Image.Image, chapter: str, progress: float, url: str = "") -> None:
    d = ImageDraw.Draw(img)
    if chapter:
        f = vfont(21, 700)
        x = 74
        for ch in chapter.upper():
            d.text((x, 54), ch, font=f, fill=(150, 162, 184))
            x += text_width(d, ch, f) + 3.2
        d.rectangle((74, 88, 74 + int(text_width(d, chapter.upper(), f) + 3.2 * len(chapter)), 90),
                    fill=(255, 77, 90, 170))
    # progress bar
    d.rectangle((0, H - 6, W, H), fill=(16, 20, 29))
    d.rectangle((0, H - 6, int(W * progress), H), fill=(255, 77, 90))


_scrim_cache: Image.Image | None = None


def caption_scrim() -> Image.Image:
    """Pre-blurred band behind the captions — built once, composited per frame."""
    global _scrim_cache
    if _scrim_cache is None:
        band = Image.new("RGBA", (W, 150), (0, 0, 0, 0))
        bd = ImageDraw.Draw(band)
        bd.rectangle((0, 0, W, 150), fill=(6, 8, 13, 195))
        band = band.filter(__import__("PIL.ImageFilter", fromlist=["ImageFilter"]).GaussianBlur(12))
        _scrim_cache = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        _scrim_cache.alpha_composite(band, (0, CAPTION_TOP - 16))
    return _scrim_cache


def captions(img: Image.Image, text: str, alpha: float = 1.0) -> None:
    if not text or alpha <= 0.01:
        return
    d = ImageDraw.Draw(img)
    f = vfont(30, 500)
    lines = wrap(d, text, f, W - 520)
    lh = 40
    total = lh * len(lines)
    y0 = CAPTION_TOP + (96 - total) / 2 - 6
    img.alpha_composite(caption_scrim())
    for i, line in enumerate(lines):
        w = text_width(d, line, f)
        d.text(((W - w) / 2, y0 + i * lh), line, font=f, fill=(226, 232, 242, int(255 * alpha)))


# ----------------------------------------------------------------------------- text cache
_line_cache: dict[tuple, Image.Image] = {}


def line_img(text: str, f: ImageFont.FreeTypeFont, color) -> Image.Image:
    key = (text, id(f), color)
    img = _line_cache.get(key)
    if img is None:
        w = int(math.ceil(text_width(ImageDraw.Draw(Image.new("RGB", (1, 1))), text, f))) + 8
        h = int(f.size * 1.6) + 8
        img = Image.new("RGBA", (max(w, 2), h), (0, 0, 0, 0))
        ImageDraw.Draw(img).text((4, 4), text, font=f, fill=color)
        _line_cache[key] = img
    return img


def blit(img: Image.Image, text: str, x: float, y: float, f, color, alpha: float = 1.0) -> float:
    if alpha <= 0.01:
        return 0
    li = line_img(text, f, color)
    if alpha < 1.0:
        li = li.copy()
        li.putalpha(li.getchannel("A").point(lambda v: int(v * alpha)))
    img.alpha_composite(li, (int(x), int(y)))
    return li.width


# ----------------------------------------------------------------------------- narration
SPEAK_MAP = {"dot": "dot", "slash": "slash", "dash": "dash", "at": "at", "comma": "comma"}
CAPTION_MAP = {"dot": ".", "slash": "/", "dash": "-", "at": "@", "comma": ","}


def spoken(text: str) -> str:
    return re.sub(r"\{\s*([^}]+?)\s*\}", lambda m: SPEAK_MAP.get(m.group(1), m.group(1)), text)


def caption(text: str) -> str:
    return re.sub(r"\{\s*([^}]+?)\s*\}", lambda m: CAPTION_MAP.get(m.group(1), m.group(1)), text)


def tts_path(text: str) -> Path:
    import hashlib
    key = hashlib.sha1(spoken(text).encode()).hexdigest()[:16]
    return TTS_DIR / f"{key}.wav"


def synth(text: str) -> Path:
    p = tts_path(text)
    if p.exists():
        return p
    TTS_DIR.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".txt")
    tmp.write_text(spoken(text) + "\n")
    subprocess.run(
        [str(PIPER), "-m", "piper", "-m", str(VOICE), "-i", str(tmp), "-f", str(p)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    tmp.unlink(missing_ok=True)
    return p


def wav_duration(p: Path) -> float:
    with wave.open(str(p), "rb") as w:
        return w.getnframes() / w.getframerate()


# ----------------------------------------------------------------------------- footage
LAB_CP = ":".join([
    "lib/log4j-api-2.26.1.jar", "lib/log4j-core-2.26.1.jar",
    *sorted(str(p) for p in Path(ROOT / "lib").glob("groovy*.jar")),
])


def run(cmd: list[str], timeout: int = 90) -> str:
    try:
        p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
        return (p.stdout + p.stderr).strip()
    except Exception as exc:  # noqa: BLE001
        return f"<capture failed: {exc}>"


def capture_footage() -> dict[str, list[list[str]]]:
    """Every terminal scene pulls its text from here — captured from the real lab."""
    marker = "/tmp/log4j-lab-pwned.txt"
    footage: dict[str, list[list[str]]] = {}

    Path(marker).unlink(missing_ok=True)
    out = run(["java", "-cp", f"{LAB_CP}:lab/build/victim:lab/poison", "lab.ClasspathPoison"])
    footage["victim_poison"] = [out.splitlines()]

    Path(marker).unlink(missing_ok=True)
    out = run(["java", "-cp", f"{LAB_CP}:lab/build/victim", "lab.ClasspathPoison"])
    footage["victim_clean"] = [out.splitlines()]

    out = run(["java", "-cp", f"lib/log4j-api-2.26.1.jar:lab/build/victim:lab/poison", "lab.ApiOnly"])
    footage["api_only"] = [out.splitlines()]

    listing = run(["unzip", "-l", "lab/build/evil-dependency.jar"])
    Path(marker).unlink(missing_ok=True)
    jar = run(["java", "-cp", f"{LAB_CP}:lab/build/victim:lab/build/evil-dependency.jar", "lab.ClasspathPoison"])
    footage["jar_run"] = [listing.splitlines(), jar.splitlines()]

    out = run(["python3", "lab/proxy_capture.py", "java", "-cp",
               f"{LAB_CP}:lab/build/victim:lab/poison-proxy", "lab.ProxyVictim"], timeout=120)
    footage["proxy"] = [out.splitlines()]
    return footage


def colour_for(line: str) -> tuple:
    s = line.strip()
    if s.startswith("===") or "PAYLOAD EXECUTED" in s or "END PAYLOAD" in s:
        return ACCENT
    if s.startswith("PASS"):
        return GREEN
    if s.startswith("uid="):
        return AMBER
    if s.startswith("GET ") or s.startswith("HTTP/"):
        return AMBER
    if s.startswith("---"):
        return CYAN
    if "could not find a logging provider" in s:
        return AMBER
    if s.startswith("[") and "null" in s:
        return TEXT_2
    return TEXT


# ----------------------------------------------------------------------------- scenes
def scene_title(sc: dict, t: float, d: float) -> Image.Image:
    img = background()
    a = ramp(t, 0.0, 0.7)
    f = vfont(92, 800)
    fs = vfont(38, 500)
    fb = vfont(24, 600)
    d_ = ImageDraw.Draw(img)
    lines = wrap(d_, TITLE, f, 1500)
    y = 300
    for i, ln in enumerate(lines):
        blit(img, ln, 96, y + i * 104, f, TEXT, a)
    bar_w = int(130 * ramp(t, 0.5, 0.6))
    d_.rectangle((96, y + len(lines) * 104 + 20, 96 + bar_w, y + len(lines) * 104 + 27), fill=ACCENT)
    y2 = y + len(lines) * 104 + 70
    for i, ln in enumerate(wrap(d_, SUBTITLE, fs, 1080)):
        blit(img, ln, 96, y2 + i * 50, fs, TEXT_2, ramp(t, 0.9 + i * 0.08, 0.5))
    badges = [("Proof of concept", ACCENT), ("Log4j 2.14.1 – 2.26.1", CYAN),
              ("CVSS 7.8 High", AMBER), ("First disclosure", TEXT_2)]
    x = 96
    for text, col in badges:
        w = int(text_width(d_, text, fb)) + 44
        yb = 700
        layer = Image.new("RGBA", (w, 52), (0, 0, 0, 0))
        ld = ImageDraw.Draw(layer)
        ld.rounded_rectangle((0, 0, w, 52), radius=26, outline=col + (110,), width=2)
        ld.text((22, 14), text, font=fb, fill=col)
        layer.putalpha(layer.getchannel("A").point(lambda v: int(v * ramp(t, 1.5 + 0.12 * badges.index((text, col)), 0.5))))
        img.alpha_composite(layer, (x, yb))
        x += w + 18
    fu = vfont(26, 600)
    blit(img, REPO, 96, 806, fu, TEXT, ramp(t, 2.2, 0.6))
    return img


def scene_concept(sc: dict, t: float, d: float) -> Image.Image:
    img = background()
    d_ = ImageDraw.Draw(img)
    blocks = [
        ("Logging library",
         "Applications write lines into their log files: user logged in, request failed, payment declined."),
        ("It runs inside the app",
         "Same process, same privileges, same memory. Log4j is trusted code in every application that uses it."),
        ("The classpath",
         "The list of jars and folders the JVM searches for code. Log4j is on it — and so is anything else that gets there."),
    ]
    fb = vfont(36, 700)
    fp = vfont(28, 400)
    y = 190
    for i, (head, body) in enumerate(blocks):
        a = ramp(t, 0.25 + i * 0.45, 0.5)
        x = 90 + int(lerp(-40, 0, ramp(t, 0.25 + i * 0.45, 0.5)))
        d_.ellipse((x, y + 12, x + 16, y + 28), fill=ACCENT)
        blit(img, head, x + 36, y, fb, TEXT, a)
        for j, ln in enumerate(wrap(d_, body, fp, 700)):
            blit(img, ln, x + 36, y + 56 + j * 40, fp, TEXT_2, a)
        y += 215

    # classpath stack on the right
    px, pw = 1000, 830
    a = ramp(t, 1.5, 0.6)
    layer = Image.new("RGBA", (pw, 560), (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)
    ld.rounded_rectangle((0, 0, pw, 560), radius=18, fill=SURFACE + (238,), outline=BORDER + (255,), width=2)
    ld.text((32, 26), "the classpath of a Java application", font=vfont(25, 600), fill=MUTED)
    rows = [("my-app.jar", TEXT_2, False), ("spring-web-6.1.jar", TEXT_2, False),
            ("log4j-api-2.26.1.jar", CYAN, False), ("log4j-core-2.26.1.jar", CYAN, False),
            ("...anything else that lands here", ACCENT, True)]
    yy = 84
    fm = font("mono", 28, 400)
    for name, col, hot in rows:
        ld.rounded_rectangle((32, yy, pw - 32, yy + 66), radius=10,
                             fill=(255, 77, 90, 30) if hot else (255, 255, 255, 8),
                             outline=(255, 77, 90, 120) if hot else (255, 255, 255, 20), width=2)
        ld.text((56, yy + 19), name, font=fm, fill=col)
        yy += 80
    ld.text((32, yy + 18), "Log4j reads fixed-name files from this list.", font=vfont(24, 500), fill=MUTED)
    layer.putalpha(layer.getchannel("A").point(lambda v: int(v * a)))
    img.alpha_composite(layer, (px, 190))
    return img


def scene_files(sc: dict, t: float, d: float) -> Image.Image:
    img = background()
    d_ = ImageDraw.Draw(img)
    fd = vfont(26, 400)
    fb = vfont(26, 600)
    cards = [
        ("log4j2.system.properties", "Every key is copied into the JVM's system properties.",
         ["global settings for the whole process",
          "log4j.configurationFile → attacker's file",
          "log4j2.Script.enableLanguages → Groovy"], ACCENT),
        ("log4j2.component.properties", "Log4j's own properties, read by the same API.",
         ["the same configuration hijack",
          "reached without log4j-core",
          "higher precedence than a file inside the jar"], CYAN),
    ]
    cw, ch = 850, 400
    for i, (name, desc, bullets, col) in enumerate(cards):
        a = ramp(t, 0.2 + i * 0.45, 0.55)
        x = 90 + i * (cw + 40)
        y = 190
        layer = Image.new("RGBA", (cw, ch), (0, 0, 0, 0))
        ld = ImageDraw.Draw(layer)
        ld.rounded_rectangle((0, 0, cw, ch), radius=18, fill=SURFACE + (238,), outline=col + (150,), width=2)
        ld.rounded_rectangle((0, 0, cw, 9), radius=4, fill=col)
        ld.text((34, 44), name, font=font("mono", 29, 700), fill=col)
        yy = 112
        for ln in wrap(d_, desc, fd, cw - 68):
            ld.text((34, yy), ln, font=fd, fill=TEXT)
            yy += 38
        yy += 22
        for b in bullets:
            ld.text((34, yy), "—", font=fb, fill=col)
            ld.text((70, yy), b, font=fb, fill=TEXT_2)
            yy += 42
        layer.putalpha(layer.getchannel("A").point(lambda v: int(v * a)))
        img.alpha_composite(layer, (x, y))
    # bottom strip
    a = ramp(t, 1.3, 0.5)
    layer = Image.new("RGBA", (1740, 104), (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)
    ld.rounded_rectangle((0, 0, 1740, 104), radius=14, fill=(255, 77, 90, 28), outline=(255, 77, 90, 110), width=2)
    ld.text((36, 34), "Neither file has to be requested. Neither has to be enabled. Log4j prints no warning when it finds them.",
            font=vfont(27, 600), fill=TEXT)
    layer.putalpha(layer.getchannel("A").point(lambda v: int(v * a)))
    img.alpha_composite(layer, (90, 650))
    return img


def scene_code(sc: dict, t: float, d: float) -> Image.Image:
    img = background()
    d_ = ImageDraw.Draw(img)
    fm = font("mono", 27, 400)
    code = sc["code"]
    x0 = 90
    w = 1080
    lh = 46
    panel_h = lh * len(code) + 86
    y0 = max(150, 160 + (CONTENT_BOTTOM - 160 - panel_h) // 2)
    layer = Image.new("RGBA", (w, panel_h), (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)
    ld.rounded_rectangle((0, 0, w, panel_h), radius=16, fill=TERM_BG + (240,), outline=BORDER + (255,), width=2)
    ld.rounded_rectangle((0, 0, w, 56), radius=16, fill=TERM_CHROME + (255,))
    ld.rectangle((0, 36, w, 56), fill=TERM_CHROME + (255,))
    for k, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        ld.ellipse((24 + k * 26, 20, 38 + k * 26, 34), fill=c)
    ld.text((w / 2 - 150, 18), sc["file"], font=font("mono", 23, 500), fill=MUTED)
    colors = {"comment": (104, 120, 145), "key": (255, 138, 128), "plain": (210, 220, 236),
              "tag": (140, 196, 255)}
    for i, (text, kind) in enumerate(code):
        ly = 86 + i * lh
        if kind == "key":
            ld.rounded_rectangle((16, ly - 8, w - 16, ly + lh - 10), radius=8, fill=(255, 77, 90, 22))
        ld.text((34, ly), text, font=fm, fill=colors.get(kind, TEXT))
    layer.putalpha(layer.getchannel("A").point(lambda v: int(v * ramp(t, 0.1, 0.5))))
    img.alpha_composite(layer, (x0, y0))
    # annotations
    for n, (line_idx, text, side) in enumerate(sc.get("annotations", [])):
        start = 1.1 + n * 0.9
        a = ramp(t, start, 0.5)
        if a <= 0:
            continue
        ly = y0 + 86 + line_idx * lh
        hl = Image.new("RGBA", (w, panel_h), (0, 0, 0, 0))
        hd = ImageDraw.Draw(hl)
        hd.rounded_rectangle((16, ly - 8, w - 16, ly + lh - 10), radius=8,
                             outline=(255, 77, 90, 220), width=2, fill=(255, 77, 90, 26))
        img.alpha_composite(hl, (x0, y0))
        cx = x0 + w + 70
        cy = ly - 34
        cw = 620
        fa = vfont(25, 500)
        lines = wrap(d_, text, fa, cw - 48)
        ch = 26 + len(lines) * 36
        box = Image.new("RGBA", (cw, ch), (0, 0, 0, 0))
        bd = ImageDraw.Draw(box)
        bd.rounded_rectangle((0, 0, cw, ch), radius=14, fill=SURFACE + (240,), outline=ACCENT + (140,), width=2)
        for j, ln in enumerate(lines):
            bd.text((24, 20 + j * 36), ln, font=fa, fill=TEXT)
        box.putalpha(box.getchannel("A").point(lambda v: int(v * a)))
        img.alpha_composite(box, (cx, cy))
        # connector
        conn = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        cd = ImageDraw.Draw(conn)
        cd.line([(x0 + w - 10, ly + lh / 2 - 6), (cx - 12, cy + ch / 2)], fill=ACCENT + (int(190 * a),), width=3)
        cd.ellipse((cx - 18, cy + ch / 2 - 6, cx - 6, cy + ch / 2 + 6), fill=ACCENT + (int(230 * a),))
        img.alpha_composite(conn)
    return img


def scene_terminal(sc: dict, t: float, d: float, footage: dict) -> Image.Image:
    img = background()
    d_ = ImageDraw.Draw(img)
    steps = sc.get("steps", [])
    blocks = footage.get(sc.get("footage", ""), [])
    if sc.get("replay"):
        steps = [dict(cmd="", note="")]

    tx, ty, tw = 80, 168, 1180
    fm = font("mono", 22, 400)
    lh = 30
    max_lines = 20
    max_chars = 82
    timeline: list[tuple[float, str, str]] = []  # (time, kind, payload)

    if sc.get("replay"):
        t_cursor = 0.25
        for b in blocks:
            for ln in b:
                timeline.append((t_cursor, "line", ln))
                t_cursor += 0.2
    else:
        t_cursor = 0.25
        block_idx = 0
        for step in steps:
            timeline.append((t_cursor, "cmd", step["cmd"]))
            t_cursor += len(step["cmd"]) / 42.0 + 0.5
            if step.get("note"):
                timeline.append((t_cursor, "note", step["note"]))
                t_cursor += 0.45
            if step.get("no_output"):
                t_cursor += 0.35
                continue
            block = blocks[block_idx] if block_idx < len(blocks) else []
            block_idx += 1
            t_cursor += 0.9 if step["cmd"].startswith(("java", "python3")) else 0.3
            for ln in block:
                timeline.append((t_cursor, "line", ln))
                t_cursor += 0.18
            t_cursor += 0.15

    visible: list[tuple[str, tuple, bool]] = []
    # stretch (or compress) the visual timeline so the action spans the narration
    natural = (timeline[-1][0] + 0.4) if timeline else 1.0
    factor = max(0.8, min(2.6, (d - 0.5) / natural)) if natural else 1.0
    timeline = [(w * factor, k, p) for w, k, p in timeline]
    for when, kind, payload in timeline:
        if t < when:
            break
        if kind == "cmd":
            chars = int((t - when) * 42 / factor) + 1
            visible.append(("$ " + payload[:chars], CYAN, True))
            if chars < len(payload):
                break
        elif kind == "note":
            visible.append(("  " + payload, MUTED, False))
        else:
            visible.append((payload, colour_for(payload), False))
    scrolled = max(0, len(visible) - max_lines)
    visible = visible[-max_lines:]

    panel_h = 690
    layer = Image.new("RGBA", (tw, panel_h), (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)
    ld.rounded_rectangle((0, 0, tw, panel_h), radius=16, fill=TERM_BG + (242,), outline=BORDER + (255,), width=2)
    ld.rounded_rectangle((0, 0, tw, 52), radius=16, fill=TERM_CHROME + (255,))
    ld.rectangle((0, 34, tw, 52), fill=TERM_CHROME + (255,))
    for k, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        ld.ellipse((24 + k * 26, 18, 38 + k * 26, 32), fill=c)
    ld.text((tw / 2 - 250, 16), "bash — log4j-classpath-plant-repo", font=font("mono", 21, 500), fill=MUTED)
    for i, (text, col, is_prompt) in enumerate(visible):
        ly = 66 + i * lh
        if is_prompt:
            ld.rounded_rectangle((14, ly - 5, tw - 14, ly + lh - 6), radius=8, fill=(79, 195, 247, 22))
        ld.text((30, ly), text[:max_chars], font=fm, fill=col)
    if scrolled:
        ld.text((30, 66 + max_lines * lh + 6), f"↑ {scrolled} earlier lines", font=font("mono", 19, 400), fill=MUTED)
    a = ramp(t, 0.05, 0.35)
    layer.putalpha(layer.getchannel("A").point(lambda v: int(v * a)))
    img.alpha_composite(layer, (tx, ty))

    # callouts on the right
    callouts = [(s["note"], 0.4 + i * 0.5, CYAN) for i, s in enumerate(steps) if s.get("note")]
    callouts += [(c[0], c[1], c[2] if len(c) > 2 else ACCENT) for c in sc.get("callouts", [])]
    for i, (note, start, col) in enumerate(callouts):
        al = ramp(t, start * factor, 0.5)
        if al <= 0:
            continue
        cw = 520
        fa = vfont(25, 500)
        ls = wrap(d_, note, fa, cw - 48)
        ch = 26 + len(ls) * 36
        cy = 190 + i * (ch + 26)
        box = Image.new("RGBA", (cw, ch), (0, 0, 0, 0))
        bd = ImageDraw.Draw(box)
        bd.rounded_rectangle((0, 0, cw, ch), radius=14, fill=SURFACE + (238,), outline=col + (130,), width=2)
        for j, ln in enumerate(ls):
            bd.text((24, 20 + j * 36), ln, font=fa, fill=TEXT)
        box.putalpha(box.getchannel("A").point(lambda v: int(v * al)))
        img.alpha_composite(box, (1310, cy))
    if sc.get("footer"):
        blit(img, sc["footer"], 82, ty + panel_h + 18, vfont(23, 500), MUTED, ramp(t, 0.6, 0.5))
    return img


def scene_bullets(sc: dict, t: float, d: float) -> Image.Image:
    img = background()
    d_ = ImageDraw.Draw(img)
    fh = vfont(32, 700)
    fd = vfont(25, 400)
    items = sc["items"]
    y = 176
    for i, (head, body) in enumerate(items):
        start = 0.2 + i * 0.55
        a = ramp(t, start, 0.45)
        x = 96 + int(lerp(-36, 0, ramp(t, start, 0.45)))
        blit(img, f"{i + 1}", x, y + 2, vfont(28, 800), ACCENT, a)
        blit(img, head, x + 52, y, fh, TEXT, a)
        yy = y + 50
        for ln in wrap(d_, body, fd, 1560):
            blit(img, ln, x + 52, yy, fd, TEXT_2, a)
            yy += 36
        y = yy + 22
    return img


def scene_table(sc: dict, t: float, d: float) -> Image.Image:
    img = background()
    d_ = ImageDraw.Draw(img)
    fh = vfont(26, 700)
    fr = vfont(25, 400)
    cols = [640, 540, 560]
    x0 = 96
    header = ["", "Log4Shell (CVE-2021-44228)", "This finding"]
    header[0] = sc["headers"][0]
    xs = [x0]
    for c in cols:
        xs.append(xs[-1] + c)
    y = 190
    layer = Image.new("RGBA", (1740, 78), (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)
    ld.rounded_rectangle((0, 0, 1740, 78), radius=12, fill=SURFACE_2 + (235,))
    for i, h in enumerate(header):
        col = MUTED if i == 0 else (TEXT_2 if i == 1 else ACCENT)
        ld.text((xs[i] + 22, 24), h, font=fh, fill=col)
    layer.putalpha(layer.getchannel("A").point(lambda v: int(v * ramp(t, 0.15, 0.4))))
    img.alpha_composite(layer, (x0, y))
    y += 92
    for r, row in enumerate(sc["rows"]):
        start = 0.45 + r * 0.3
        a = ramp(t, start, 0.4)
        if a <= 0:
            y += 70
            continue
        rl = Image.new("RGBA", (1740, 66), (0, 0, 0, 0))
        rd = ImageDraw.Draw(rl)
        rd.rectangle((0, 0, 1740, 66), fill=(255, 255, 255, 8) if r % 2 == 0 else (0, 0, 0, 0))
        rd.text((xs[0] + 22, 20), row[0], font=fr, fill=TEXT)
        rd.text((xs[1] + 22, 20), row[1], font=fr, fill=TEXT_2)
        rd.text((xs[2] + 22, 20), row[2], font=fr, fill=TEXT)
        rl.putalpha(rl.getchannel("A").point(lambda v: int(v * a)))
        img.alpha_composite(rl, (x0, y))
        y += 70
    return img


def scene_diagram(sc: dict, t: float, d: float) -> Image.Image:
    img = background()
    d_ = ImageDraw.Draw(img)
    fh = vfont(27, 600)
    fm = font("mono", 24, 500)
    nodes = [
        (120, 180, 520, 104, "one small text file\non a classpath", ACCENT, "mono"),
        (700, 180, 520, 104, "build agent · shared host\n· one dependency", TEXT, "sans"),
        (1280, 180, 520, 104, "normal packaging\nnothing in the pipeline objects", TEXT, "sans"),
        (1280, 400, 520, 104, "staging · production\nevery region · every consumer", TEXT, "sans"),
        (700, 400, 520, 104, "applied again\non every start-up", TEXT, "sans"),
        (120, 400, 520, 104, "every application\nthat loads it", ACCENT, "sans"),
    ]
    for i, (x, y, w, h, text, col, kind) in enumerate(nodes):
        a = ramp(t, 0.2 + i * 0.3, 0.45)
        if a <= 0:
            continue
        layer = Image.new("RGBA", (w, h), (0, 0, 0, 0))
        ld = ImageDraw.Draw(layer)
        ld.rounded_rectangle((0, 0, w, h), radius=14, fill=SURFACE + (235,), outline=col + (130,), width=2)
        f = fm if kind == "mono" else fh
        lines = text.split("\n")
        for j, ln in enumerate(lines):
            tw_ = ld.textlength(ln, font=f)
            ld.text(((w - tw_) / 2, 20 + j * 36), ln, font=f, fill=col)
        layer.putalpha(layer.getchannel("A").point(lambda v: int(v * a)))
        img.alpha_composite(layer, (x, y))
    arrows = [((640, 232), (700, 232)), ((1220, 232), (1280, 232)),
              ((1540, 284), (1540, 400)), ((1280, 452), (1220, 452)),
              ((700, 452), (640, 452))]
    for i, (p0, p1) in enumerate(arrows):
        a = ramp(t, 1.4 + i * 0.18, 0.4)
        if a <= 0:
            continue
        layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        ld = ImageDraw.Draw(layer)
        ld.line([p0, p1], fill=(150, 165, 190, int(190 * a)), width=3)
        ang = math.atan2(p1[1] - p0[1], p1[0] - p0[0])
        for s in (-1, 1):
            ld.line([p1, (p1[0] - 16 * math.cos(ang + s * 0.45), p1[1] - 16 * math.sin(ang + s * 0.45))],
                    fill=(150, 165, 190, int(190 * a)), width=3)
        img.alpha_composite(layer)
    a = ramp(t, 3.0, 0.5)
    if a > 0:
        layer = Image.new("RGBA", (1740, 92), (0, 0, 0, 0))
        ld = ImageDraw.Draw(layer)
        ld.rounded_rectangle((0, 0, 1740, 92), radius=14, fill=(255, 194, 75, 26), outline=(255, 194, 75, 110), width=2)
        ld.text((36, 28), "Analysis of the mechanism — not a measured compromise of a real pipeline.",
                font=vfont(26, 600), fill=AMBER)
        layer.putalpha(layer.getchannel("A").point(lambda v: int(v * a)))
        img.alpha_composite(layer, (96, 620))
    return img


def scene_closing(sc: dict, t: float, d: float) -> Image.Image:
    img = background()
    d_ = ImageDraw.Draw(img)
    fh = vfont(54, 800)
    fb = vfont(28, 500)
    blit(img, "This is a first disclosure.", 96, 260, fh, TEXT, ramp(t, 0.2, 0.6))
    lines = [
        ("Report text: published in the repository", TEXT_2),
        ("Goes to the Apache Logging Services security team — security@apache.org", TEXT_2),
        ("Found in the same audit as a second Log4j finding; both reported together", TEXT_2),
    ]
    for i, (text, col) in enumerate(lines):
        a = ramp(t, 0.8 + i * 0.4, 0.5)
        blit(img, "•", 100, 372 + i * 46, fb, ACCENT, a)
        blit(img, text, 140, 372 + i * 46, fb, col, a)
    a = ramp(t, 2.1, 0.6)
    box = Image.new("RGBA", (1728, 150), (0, 0, 0, 0))
    ld = ImageDraw.Draw(box)
    ld.rounded_rectangle((0, 0, 1728, 150), radius=18, fill=SURFACE + (235,), outline=ACCENT + (140,), width=2)
    ld.text((36, 26), "github.com/vindeckyy/log4j-classpath-plant-rce", font=vfont(34, 700), fill=TEXT)
    ld.text((36, 82), "full analysis · reproduction steps · detection script · disclosure record",
            font=vfont(24, 400), fill=MUTED)
    box.putalpha(box.getchannel("A").point(lambda v: int(v * a)))
    img.alpha_composite(box, (96, 590))
    blit(img, "If you run Log4j, forward the report.", 96, 780, vfont(30, 600), TEXT, ramp(t, 2.6, 0.5))
    return img


RENDERERS = {
    "title": scene_title,
    "concept": scene_concept,
    "files": scene_files,
    "code": scene_code,
    "terminal": scene_terminal,
    "bullets": scene_bullets,
    "table": scene_table,
    "diagram": scene_diagram,
    "closing": scene_closing,
}


# ----------------------------------------------------------------------------- build
def build_plan() -> list[dict]:
    plan = []
    for sc in SCENES:
        clips = []
        for sent in sc["narration"]:
            p = synth(sent)
            clips.append(dict(text=caption(sent), wav=p, dur=wav_duration(p)))
        plan.append(dict(scene=sc, clips=clips, lead=sc.get("lead", 0.4), tail=sc.get("tail", 0.4)))
    return plan


def build_audio(plan: list[dict], path: Path) -> tuple[float, list[tuple[float, float, str]]]:
    import array
    rate = 22050
    total = 0.0
    for item in plan:
        item["start"] = total + item["lead"]
        t = item["start"]
        for clip in item["clips"]:
            clip["t0"] = t
            t += clip["dur"] + 0.22
        item["end"] = t + item["tail"]
        total = item["end"]
    buf = array.array("h", [0]) * int(total * rate)
    captions_out = []
    for item in plan:
        for clip in item["clips"]:
            with wave.open(str(clip["wav"]), "rb") as w:
                frames = w.readframes(w.getnframes())
                data = array.array("h")
                data.frombytes(frames)
            start = int(clip["t0"] * rate)
            end = min(len(buf), start + len(data))
            buf[start:end] = data[: end - start]
            captions_out.append((clip["t0"], clip["t0"] + clip["dur"], clip["text"]))
    path.parent.mkdir(parents=True, exist_ok=True)
    with wave.open(str(path), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(buf.tobytes())
    return total, captions_out


def write_srt(caps: list[tuple[float, float, str]], path: Path) -> None:
    def ts(x: float) -> str:
        h = int(x // 3600)
        m = int((x % 3600) // 60)
        s = x % 60
        return f"{h:02d}:{m:02d}:{s:06.3f}".replace(".", ",")

    lines = []
    for i, (a, b, text) in enumerate(caps, 1):
        lines.append(f"{i}\n{ts(a)} --> {ts(b)}\n{text}\n")
    path.write_text("\n".join(lines))


def caption_at(caps: list[tuple[float, float, str]], t: float) -> tuple[str, float]:
    for a, b, text in caps:
        if a <= t < b:
            return text, 1.0
        if a - 0.25 <= t < a:
            return text, ramp(t, a - 0.25, 0.25)
    return "", 0.0


def render(plan, footage, caps, out_mp4: Path, total: float, preview_dir: Path | None) -> None:
    out_mp4.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["ffmpeg", "-y", "-loglevel", "error",
           "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{W}x{H}", "-r", str(FPS), "-i", "-",
           "-c:v", "libx264", "-preset", "medium", "-crf", "18", "-pix_fmt", "yuv420p",
           "-movflags", "+faststart", str(out_mp4)]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    frames = int(total * FPS)
    current = None
    for i in range(frames):
        t = i / FPS
        item = next((it for it in plan if it["start"] <= t < it["end"]), None)
        if item is None:
            img = background()
            chrome(img, "", t / total)
            frame = img.convert("RGB")
        else:
            sc = item["scene"]
            if sc["id"] != current:
                current = sc["id"]
                print(f"  [{t:7.1f}s] scene {current}", flush=True)
            local = t - item["start"]
            dur = item["end"] - item["start"]
            renderer = RENDERERS[sc["kind"]]
            if sc["kind"] == "terminal":
                img = renderer(sc, local, dur, footage)
            else:
                img = renderer(sc, local, dur)
            fade_in = min(1.0, local / 0.35)
            fade_out = min(1.0, max(0.0, (item["end"] - t) / 0.35))
            a = min(fade_in, fade_out)
            cap, ca = caption_at(caps, t)
            captions(img, cap, ca)
            chrome(img, sc.get("chapter", ""), t / total)
            if a < 1.0:
                img = Image.blend(background(), img, a)
            frame = img.convert("RGB")
        if preview_dir is not None:
            preview_dir.mkdir(parents=True, exist_ok=True)
            frame.save(preview_dir / f"frame_{i:06d}.png")
        else:
            proc.stdin.write(frame.tobytes())
        if i % 300 == 0:
            print(f"  frame {i}/{frames}  ({t:.1f}s / {total:.1f}s)", flush=True)
    if preview_dir is None:
        proc.stdin.close()
        proc.wait()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scene", help="render only this scene id")
    ap.add_argument("--preview", action="store_true", help="write PNG frames instead of a video")
    ap.add_argument("--still", help="render one frame: <scene-id>:<seconds>")
    ap.add_argument("--no-audio", action="store_true")
    ap.add_argument("--out", default=str(OUT / "log4j-classpath-plant-poc.mp4"))
    args = ap.parse_args()

    if not VOICE.exists():
        print(f"voice model missing: {VOICE}", file=sys.stderr)
        return 2

    if args.still:
        sid, _, when = args.still.partition(":")
        sc = next((s for s in SCENES if s["id"] == sid), None)
        if sc is None:
            print(f"no scene {sid}", file=sys.stderr)
            return 2
        footage = capture_footage()
        t = float(when)
        renderer = RENDERERS[sc["kind"]]
        img = renderer(sc, t, 99.0, footage) if sc["kind"] == "terminal" else renderer(sc, t, 99.0)
        chrome(img, sc.get("chapter", ""), 0.0)
        p = OUT / f"still_{sid}.png"
        img.convert("RGB").save(p)
        print(p)
        return 0

    scenes = SCENES
    if args.scene:
        scenes = [s for s in SCENES if s["id"] == args.scene]
        if not scenes:
            print(f"no scene {args.scene}", file=sys.stderr)
            return 2
    import script as script_mod
    script_mod.SCENES[:] = scenes

    print("capturing footage from lab/ ...", flush=True)
    footage = capture_footage()

    print("synthesising narration ...", flush=True)
    plan = build_plan()
    wav = OUT / "narration.wav"
    total, caps = build_audio(plan, wav)
    write_srt(caps, OUT / "log4j-classpath-plant-poc.srt")
    print(f"narration: {total:.1f}s", flush=True)

    if args.preview:
        d = OUT / "preview"
        shutil.rmtree(d, ignore_errors=True)
        render(plan, footage, caps, Path(args.out), total, d)
        print(f"frames in {d}")
        return 0

    out_mp4 = Path(args.out)
    print("rendering frames ...", flush=True)
    render(plan, footage, caps, out_mp4, total, None)

    if not args.no_audio:
        print("muxing audio ...", flush=True)
        mux = OUT / "silent.mp4"
        shutil.move(str(out_mp4), str(mux))
        subprocess.run([
            "ffmpeg", "-y", "-loglevel", "error", "-i", str(mux), "-i", str(wav),
            "-c:v", "copy", "-c:a", "aac", "-b:a", "192k", "-shortest",
            "-movflags", "+faststart", str(out_mp4),
        ], check=True)
        mux.unlink(missing_ok=True)

    print(f"wrote {out_mp4}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
