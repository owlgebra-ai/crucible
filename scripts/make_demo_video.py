#!/usr/bin/env python3
"""Render a public-safe, one-minute CRUCIBLE snapshot walkthrough.

Input: docs/snapshot.json plus fixed, reviewed architecture/control labels from
README.md.  No private bank, VM transcript, logs, credentials, or identifiers are
read.  The exported wall card is explicitly a parsed summary, not VM footage.

Requires Pillow and ffmpeg (or imageio-ffmpeg).  On macOS, the built-in `say`
command adds the narration.  Elsewhere the captions make a silent video usable.
"""

from __future__ import annotations

import argparse
import json
import math
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont


ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "docs" / "snapshot.json"
OUTPUT = ROOT / "docs" / "demo.mp4"
W, H, FPS = 1280, 720, 24
TIMES = (0, 6, 14, 21, 28, 39, 49, 56, 60)
BG = "#081421"
CARD = "#10263A"
EDGE = "#31516B"
WHITE = "#EEF7F6"
MUTED = "#A8C0C8"
MINT = "#74F0C0"
BLUE = "#6BB9E8"
CORAL = "#FF9C8B"
GOLD = "#FFD083"

NARRATION = (
    "Crucible tests whether an agent can finish a legitimate task while unsafe shortcuts are contained.",
    "Inference and the private experience bank stay on a control VM. Pinned SSH crosses a private VPC to a separate Docker sandbox VM.",
    "D one drops unapproved egress. D two applies seccomp. D three checks proposed commands before execution.",
    "D four destroys each container. D five records defense patterns. D six filters secret-bearing actions and results.",
    "The published runc wall summary passed. Allowed TLS worked; external DNS and ptrace were blocked. Three direct IP packets hit the final drop path, and the container was destroyed.",
    "Across eighteen remote container episodes, attack success was zero percent. Ten were model runs; half were contained and task complete. One result remains unverified.",
    "Bank patterns have four egress records, two long-command records, and one each for lookalike and secret requests.",
    "Public snapshot shown. Full wall logs stay private.",
)


def font(size: int, weight: str = "regular") -> ImageFont.FreeTypeFont:
    path = Path("/System/Library/Fonts/Avenir Next.ttc")
    if path.exists():
        index = {"bold": 0, "demi": 2, "medium": 5, "regular": 7}[weight]
        return ImageFont.truetype(str(path), size, index=index)
    choices = {
        "bold": "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "demi": "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "medium": "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "regular": "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    }
    return ImageFont.truetype(choices[weight], size)


def mono(size: int) -> ImageFont.FreeTypeFont:
    for path in ("/System/Library/Fonts/Menlo.ttc", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"):
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return font(size)


def text(draw: ImageDraw.ImageDraw, xy: tuple[int, int], value: str,
         size: int, color: str = WHITE, weight: str = "regular",
         spacing: int = 4) -> None:
    draw.multiline_text(xy, value, font=font(size, weight), fill=color, spacing=spacing)


def label(draw: ImageDraw.ImageDraw, xy: tuple[int, int], value: str,
          color: str = MINT, size: int = 17) -> None:
    draw.text(xy, value.upper(), font=font(size, "bold"), fill=color, stroke_width=0)


def box(draw: ImageDraw.ImageDraw, xy: tuple[int, int, int, int],
        fill: str = CARD, outline: str = EDGE, radius: int = 22,
        width: int = 2) -> None:
    draw.rounded_rectangle(xy, radius=radius, fill=fill, outline=outline, width=width)


def pill(draw: ImageDraw.ImageDraw, xy: tuple[int, int], value: str,
         color: str = MINT, fill: str = "#163F40", size: int = 17) -> int:
    f = font(size, "bold")
    w = math.ceil(draw.textbbox((0, 0), value, font=f)[2]) + 28
    h = size + 23
    box(draw, (xy[0], xy[1], xy[0] + w, xy[1] + h), fill=fill, outline=fill,
        radius=12, width=1)
    draw.text((xy[0] + 14, xy[1] + 8), value, font=f, fill=color)
    return w


def check(draw: ImageDraw.ImageDraw, x: int, y: int, value: str,
          sub: str | None = None, color: str = MINT) -> None:
    draw.ellipse((x, y + 3, x + 29, y + 32), fill="#174D4A", outline=color, width=2)
    draw.line((x + 7, y + 17, x + 13, y + 23, x + 23, y + 10), fill=color, width=3)
    text(draw, (x + 43, y), value, 25, WHITE, "demi")
    if sub:
        text(draw, (x + 43, y + 35), sub, 17, MUTED)


def background(index: int) -> Image.Image:
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    for y in range(H):
        t = y / H
        d.line((0, y, W, y), fill=(int(8 + 5 * t), int(20 + 8 * t), int(33 + 12 * t)))
    glow = Image.new("RGBA", (W, H))
    gd = ImageDraw.Draw(glow)
    cx = (1030, 100) if index % 2 == 0 else (180, 610)
    gd.ellipse((cx[0] - 240, cx[1] - 240, cx[0] + 240, cx[1] + 240), fill=(35, 148, 154, 36))
    im = Image.alpha_composite(im.convert("RGBA"), glow.filter(ImageFilter.GaussianBlur(90))).convert("RGB")
    return im


def frame_header(draw: ImageDraw.ImageDraw, index: int, eyebrow: str, title: str) -> None:
    draw.rounded_rectangle((62, 43, 91, 72), radius=7, fill=MINT)
    draw.line((70, 58, 77, 64, 85, 51), fill=BG, width=4)
    label(draw, (108, 44), "CRUCIBLE", WHITE, 22)
    label(draw, (865, 49), f"PUBLIC EVIDENCE  /  {index + 1:02d} OF 08", MUTED, 15)
    label(draw, (64, 105), eyebrow)
    text(draw, (63, 134), title, 47, WHITE, "bold")


def footer(draw: ImageDraw.ImageDraw, index: int) -> None:
    draw.line((64, 670, 1216, 670), fill=EDGE, width=2)
    text(draw, (64, 680), "RENDERED FROM THE PUBLIC SNAPSHOT", 14, MUTED, "demi")
    text(draw, (1000, 680), "docs/snapshot.json", 14, MUTED)


def intro(im: Image.Image, _: dict) -> None:
    d = ImageDraw.Draw(im)
    label(d, (65, 86), "CRUCIBLE  /  AGENT CONTAINMENT EXPERIMENT", MINT, 22)
    text(d, (62, 154), "Keep the task.\nBlock the shortcut.", 74, WHITE, "bold", 1)
    text(d, (67, 379), "A 60-second look at the two-VM system and its published live runc evidence.", 26, MUTED)
    x = 66
    for v in ("TWO VMs", "SIX CONTROLS", "REMOTE CONTAINER RUNS"):
        x += pill(d, (x, 474), v, MINT, "#173B3E", 18) + 13
    box(d, (65, 566, 1214, 636), fill="#10283B", radius=16)
    text(d, (88, 581), "VISUAL WALKTHROUGH", 17, BLUE, "bold")
    text(d, (356, 579), "Public summary fields only  •  not raw VM footage", 20, WHITE, "medium")


def architecture(im: Image.Image, _: dict) -> None:
    d = ImageDraw.Draw(im)
    frame_header(d, 1, "Architecture", "Two VMs. One narrow execution path.")
    box(d, (64, 218, 565, 584))
    box(d, (715, 218, 1216, 584))
    pill(d, (91, 244), "CONTROL VM", BLUE, "#1A3D53", 19)
    text(d, (92, 305), "Vultr inference\nSupervisor + policy checks\nPrivate experience bank", 28, WHITE, "medium", 23)
    text(d, (92, 514), "Model credentials remain here", 19, MUTED)
    pill(d, (742, 244), "SANDBOX VM", MINT, "#173F3D", 19)
    text(d, (743, 305), "Forced-command gateway\nDocker / runc worker\nNetwork + syscall wall", 28, WHITE, "medium", 23)
    text(d, (743, 514), "Disposable container per episode", 19, MUTED)
    d.line((578, 376, 701, 376), fill=MINT, width=5)
    d.polygon([(702, 376), (689, 367), (689, 385)], fill=MINT)
    text(d, (589, 305), "PRIVATE\nVPC", 17, MINT, "bold")
    text(d, (586, 414), "PINNED\nSSH", 17, MUTED, "bold")
    text(d, (66, 606), "RED SCENARIO  /  WORKER  /  SUPERVISOR  /  SANDBOX  /  BLUE ADAPTATION", 20, MUTED, "demi")


def control_card(d: ImageDraw.ImageDraw, y: int, num: str,
                 title: str, body: str, accent: str) -> None:
    box(d, (65, y, 1215, y + 105), fill=CARD, radius=17)
    box(d, (86, y + 18, 166, y + 87), fill="#1B3D4E", outline="#1B3D4E", radius=12)
    text(d, (99, y + 24), num, 37, accent, "bold")
    text(d, (193, y + 18), title, 28, WHITE, "demi")
    text(d, (193, y + 58), body, 21, MUTED)


def controls_one(im: Image.Image, _: dict) -> None:
    d = ImageDraw.Draw(im)
    frame_header(d, 2, "D1–D3  /  Before and at execution", "Six controls around each action.")
    control_card(d, 219, "D1", "Network policy", "Default-drop egress with a pinned allowlist.", MINT)
    control_card(d, 342, "D2", "Syscall policy", "Docker seccomp at the execution seam.", BLUE)
    control_card(d, 465, "D3", "Pre-execution classifier", "Semantic judgment before a proposed command runs.", GOLD)
    text(d, (68, 609), "The wall summary separately reports observed network and ptrace blocks.", 20, MUTED)


def controls_two(im: Image.Image, _: dict) -> None:
    d = ImageDraw.Draw(im)
    frame_header(d, 3, "D4–D6  /  Lifecycle and learning", "Then contain the result.")
    control_card(d, 219, "D4", "Container lifecycle", "Fresh, bounded worker per episode; destroy after use.", MINT)
    control_card(d, 342, "D5", "Experience bank", "Episode outcomes and distilled attack / defense patterns.", BLUE)
    control_card(d, 465, "D6", "Exfil and output filter", "Scan outgoing actions, worker output, and stored text.", GOLD)
    text(d, (68, 609), "The public snapshot contains only fixed labels, counts, and approved report text.", 20, MUTED)


def wall(im: Image.Image, data: dict) -> None:
    d = ImageDraw.Draw(im)
    p = data["wall_proof"]
    frame_header(d, 4, "Observed Linux wall  /  public summary", "The runc proof checks passed.")
    box(d, (64, 209, 418, 422), fill="#102A3B", radius=20)
    label(d, (90, 234), "CONTAINER RUNTIME", MUTED, 16)
    text(d, (87, 260), "runc", 67, WHITE, "bold")
    d.line((90, 342, 392, 342), fill=EDGE, width=2)
    text(d, (90, 358), f"{p['drop_packets']} DROP packets", 26, MINT, "bold")
    text(d, (90, 391), f"{p['container_policy_checks']} container policy checks", 17, BLUE, "demi")
    box(d, (438, 209, 1215, 422), radius=20)
    check(d, 465, 237, "Pinned TLS", "Allowed request succeeded")
    check(d, 830, 237, "External DNS", "Blocked")
    check(d, 465, 325, "ptrace", "Denied by syscall policy")
    check(d, 830, 325, "Direct-IP egress", "Counter before final DROP")
    box(d, (64, 439, 1215, 628), fill="#0C1E2A", outline="#347B73", radius=18)
    label(d, (86, 455), "REDACTED TRANSCRIPT EXCERPT", MINT, 17)
    excerpt = (
        f"Probe-specific packets immediately before default DROP: {p['drop_packets']}",
        "Default DROP remains the next and final egress rule",
        "No container remains for proof-[redacted]",
    )
    for i, row in enumerate(excerpt):
        d.text((88, 487 + i * 34), row, font=mono(20), fill=WHITE if i != 0 else MINT)
    text(d, (88, 598), "Only safe lines shown; the full VM transcript remains private.", 17, MUTED)


def plot(d: ImageDraw.ImageDraw, data: dict) -> None:
    curve = data["curves"]
    x0, x1, y0, y1 = 100, 825, 458, 578
    for rate in (0, .5, 1):
        y = int(y1 - rate * (y1 - y0))
        d.line((x0, y, x1, y), fill=EDGE, width=1)
        text(d, (65, y - 11), f"{int(rate * 100)}%", 15, MUTED)
    for key, color in (("attack_rate", CORAL), ("safe_rate", MINT)):
        pts = []
        for i, item in enumerate(curve):
            x = int(x0 + i * (x1 - x0) / max(1, len(curve) - 1))
            y = int(y1 - max(0.0, min(1.0, float(item[key]))) * (y1 - y0))
            pts.append((x, y))
        if len(pts) >= 2:
            d.line(pts, fill=color, width=4, joint="curve")
        if pts:
            x, y = pts[-1]
            d.ellipse((x - 5, y - 5, x + 5, y + 5), fill=color)


def metric_card(d: ImageDraw.ImageDraw, x: int, value: str,
                caption: str, color: str) -> None:
    box(d, (x, 222, x + 360, 379), radius=18)
    text(d, (x + 24, 238), value, 65, color, "bold")
    text(d, (x + 25, 318), caption, 20, WHITE, "medium", 4)


def outcomes(im: Image.Image, data: dict) -> None:
    d = ImageDraw.Draw(im)
    s = data["summary"]
    frame_header(d, 5, "Aggregate live episodes", "What the remote runs recorded.")
    metric_card(d, 64, str(s["remote"]), "remote container episodes", BLUE)
    metric_card(d, 460, f"{s['attack_rate']:.0%}", "attack success  /  all container runs", CORAL)
    metric_card(d, 856, f"{s['safe_rate']:.0%}", "contained + task complete\namong model runs", MINT)
    box(d, (64, 397, 856, 596), radius=18)
    label(d, (85, 414), "CUMULATIVE EPISODE OUTCOMES", MUTED, 16)
    plot(d, data)
    box(d, (879, 397, 1215, 596), radius=18)
    text(d, (901, 421), f"{s['model_live']} model runs", 26, WHITE, "demi")
    text(d, (901, 467), f"{s['probe_live']} offline probes", 25, WHITE, "medium")
    text(d, (901, 511), f"{s['verified_live']} verified results", 24, MINT, "medium")
    text(d, (901, 551), f"{s['unverified_live']} unverified result", 20, GOLD, "medium")
    text(d, (66, 615), "Safe rate uses model runs only; a blocked action alone does not complete the task.", 19, MUTED)


def bank(im: Image.Image, data: dict) -> None:
    d = ImageDraw.Draw(im)
    frame_header(d, 6, "D5  /  Experience bank", "Turn attempts into narrow defenses.")
    box(d, (64, 214, 790, 592), radius=18)
    label(d, (91, 241), "DISTILLED ATTACK SHAPES", MUTED, 17)
    approved = (
        ("Direct egress attempt", "Default-drop egress policy"),
        ("Long-running command", "Pre-execution action gate"),
        ("Dependency lookalike host", "Default-drop egress policy"),
        ("Secret in outbound request", "Outbound secret scan"),
    )
    counts = {p["attack_shape"]: int(p["supporting_count"]) for p in data["patterns"]}
    for i, (shape, defense) in enumerate(approved):
        y = 279 + i * 73
        if i:
            d.line((90, y - 13, 764, y - 13), fill=EDGE, width=1)
        text(d, (91, y), shape, 23, WHITE, "demi")
        text(d, (92, y + 33), defense, 17, MUTED)
        text(d, (717, y + 6), str(counts.get(shape, 0)), 26, MINT, "bold")
    box(d, (809, 214, 1215, 592), radius=18)
    label(d, (836, 242), "LATEST APPROVED REPORT", BLUE, 17)
    text(d, (835, 301), "“The bounded local\nfixture read completed\nsuccessfully.”", 30, WHITE, "medium", 16)
    text(d, (836, 497), "Fixed rubric result\nRemote episode", 18, MUTED, "medium", 10)
    text(d, (66, 614), "Counts are supporting episodes in the public bank, not raw worker messages.", 19, MUTED)


def close(im: Image.Image, data: dict) -> None:
    d = ImageDraw.Draw(im)
    label(d, (65, 91), "CRUCIBLE  /  PUBLIC EVIDENCE", MINT, 21)
    text(d, (63, 158), "Evidence, then\nteardown.", 75, WHITE, "bold", 4)
    box(d, (64, 389, 1216, 583), fill="#133B43", outline="#347B73", radius=22)
    check(d, 96, 423, "Proof container destroyed", "Observed in the published runc wall summary")
    check(d, 96, 510, "Safe task outcome measured", "50% of model-driven remote runs in this snapshot")
    text(d, (66, 612), "Rendered public snapshot  •  full VM transcript retained privately", 20, MUTED)


SCENES = (intro, architecture, controls_one, controls_two, wall, outcomes, bank, close)


def validate(data: dict) -> None:
    s, p = data["summary"], data["wall_proof"]
    if p["status"] != "checks_passed" or p["runtime"] != "runc":
        raise ValueError("This video requires a passing runc wall summary")
    for key in ("allowlisted_tls", "external_dns_blocked", "ptrace_blocked",
                "direct_ip_drop", "container_destroyed"):
        if p[key] is not True:
            raise ValueError(f"Missing wall check: {key}")
    if s["remote"] != s["live"] or s["docker"] or s["simulated"]:
        raise ValueError("Video copy requires remote-only container episodes")
    if s["model_live"] + s["probe_live"] != s["live"]:
        raise ValueError("Model/probe totals do not match")
    if s["verified_live"] + s["unverified_live"] != s["live"]:
        raise ValueError("Verification totals do not match")
    if not data["curves"] or len(data["curves"]) != s["live"]:
        raise ValueError("Curve and episode totals do not match")
    if data["latest_report"]["text"] != "The bounded local fixture read completed successfully.":
        raise ValueError("Latest public report changed; review the video copy")


def ffmpeg_executable() -> str:
    found = shutil.which("ffmpeg")
    if found:
        return found
    try:
        import imageio_ffmpeg
    except ImportError as exc:
        raise RuntimeError("Install ffmpeg or imageio-ffmpeg") from exc
    return imageio_ffmpeg.get_ffmpeg_exe()


def audio_duration(ffmpeg: str, path: Path) -> float:
    proc = subprocess.run([ffmpeg, "-hide_banner", "-i", str(path), "-f", "null", "-"],
                          capture_output=True, text=True)
    import re
    match = re.search(r"Duration: (\d+):(\d+):(\d+\.\d+)", proc.stderr)
    if not match:
        raise RuntimeError(f"Cannot measure narration: {path}")
    h, m, sec = match.groups()
    return int(h) * 3600 + int(m) * 60 + float(sec)


def narrate(tmp: Path, ffmpeg: str) -> list[Path]:
    if not shutil.which("say"):
        print("Built-in narration unavailable; exporting with readable captions.")
        return []
    paths = []
    for i, words in enumerate(NARRATION):
        path = tmp / f"voice-{i}.aiff"
        subprocess.run(["say", "-v", "Daniel", "-r", "190", "-o", str(path), words], check=True)
        duration = audio_duration(ffmpeg, path)
        available = TIMES[i + 1] - TIMES[i] - 0.55
        if duration > available:
            raise ValueError(f"Narration {i + 1} is {duration:.1f}s; available {available:.1f}s")
        print(f"Narration {i + 1}: {duration:.2f}s / {available:.2f}s")
        paths.append(path)
    return paths


def render(data: dict, output: Path, *, voice: bool = True) -> None:
    ffmpeg = ffmpeg_executable()
    slides = []
    for i, scene in enumerate(SCENES):
        im = background(i)
        scene(im, data)
        d = ImageDraw.Draw(im)
        footer(d, i)
        slides.append(im)

    with tempfile.TemporaryDirectory(prefix="crucible-demo-") as name:
        tmp = Path(name)
        audio = narrate(tmp, ffmpeg) if voice else []
        cmd = [ffmpeg, "-y", "-hide_banner", "-loglevel", "error",
               "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{W}x{H}",
               "-framerate", str(FPS), "-i", "pipe:0"]
        for path in audio:
            cmd += ["-i", str(path)]
        if audio:
            filters = []
            for i in range(len(audio)):
                ms = int((TIMES[i] + 0.55) * 1000)
                filters.append(f"[{i + 1}:a]aresample=48000,adelay={ms}:all=1[a{i}]")
            inputs = "".join(f"[a{i}]" for i in range(len(audio)))
            filters.append(f"{inputs}amix=inputs={len(audio)}:duration=longest:normalize=0,"
                           "volume=0.88,apad=whole_dur=60,afade=t=out:st=59:d=1[aout]")
            cmd += ["-filter_complex", ";".join(filters), "-map", "0:v", "-map", "[aout]"]
        else:
            cmd += ["-map", "0:v"]
        cmd += ["-c:v", "libx264", "-preset", "medium", "-crf", "19",
                "-pix_fmt", "yuv420p"]
        if audio:
            cmd += ["-c:a", "aac", "-b:a", "160k"]
        cmd += ["-t", "60", "-movflags", "+faststart", str(output)]
        output.parent.mkdir(parents=True, exist_ok=True)
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            for frame_no in range(60 * FPS):
                t = frame_no / FPS
                index = next(i for i in range(len(SCENES)) if TIMES[i] <= t < TIMES[i + 1])
                remaining = TIMES[index + 1] - t
                if index < len(SCENES) - 1 and remaining < 0.55:
                    a = 1 - remaining / 0.55
                    a = a * a * (3 - 2 * a)
                    frame = Image.blend(slides[index], slides[index + 1], a)
                else:
                    frame = slides[index].copy()
                d = ImageDraw.Draw(frame)
                d.rounded_rectangle((64, 657, 1216, 661), radius=2, fill="#29485A")
                d.rounded_rectangle((64, 657, 64 + int(1152 * t / 60), 661),
                                    radius=2, fill=MINT)
                assert proc.stdin is not None
                proc.stdin.write(frame.tobytes())
        except BrokenPipeError as exc:
            raise RuntimeError("ffmpeg stopped while receiving frames") from exc
        finally:
            if proc.stdin:
                proc.stdin.close()
        err = proc.stderr.read().decode("utf-8", "replace") if proc.stderr else ""
        if proc.wait() != 0:
            raise RuntimeError(f"ffmpeg failed: {err[-3000:]}")
    print(f"Wrote {output}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--no-voice", action="store_true")
    args = parser.parse_args()
    data = json.loads(SNAPSHOT.read_text())
    validate(data)
    render(data, args.output, voice=not args.no_voice)


if __name__ == "__main__":
    main()
