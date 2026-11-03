#!/usr/bin/env python3
"""Renders packaging/AppIcon.png (1024x1024): a shield guarding a terminal prompt."""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

SCALE = 4
SIZE = 1024 * SCALE


def s(v):
    return v * SCALE


def cubic(p0, p1, p2, p3, steps=64):
    pts = []
    for i in range(steps + 1):
        t = i / steps
        mt = 1 - t
        x = mt**3 * p0[0] + 3 * mt * mt * t * p1[0] + 3 * mt * t * t * p2[0] + t**3 * p3[0]
        y = mt**3 * p0[1] + 3 * mt * mt * t * p1[1] + 3 * mt * t * t * p2[1] + t**3 * p3[1]
        pts.append((s(x), s(y)))
    return pts


def shield(cx=512, top=232, bottom=814, half=244, shoulder=300, waist=520):
    right = (
        cubic((cx, top), (cx + 80, top + 46), (cx + half - 60, shoulder), (cx + half, shoulder))
        + cubic((cx + half, shoulder), (cx + half + 6, shoulder + 90), (cx + half + 4, waist - 70), (cx + half - 10, waist))
        + cubic((cx + half - 10, waist), (cx + half - 34, waist + 150), (cx + 120, bottom - 60), (cx, bottom))
    )
    left = [(s(2 * cx) - x, y) for x, y in reversed(right)]
    return right + left


def vertical_gradient(size, top, bottom):
    gradient = Image.new("RGB", (1, 256))
    for y in range(256):
        t = y / 255
        gradient.putpixel((0, y), tuple(round(a + (b - a) * t) for a, b in zip(top, bottom)))
    return gradient.resize(size, Image.BICUBIC)


def main():
    canvas = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))

    # Squircle-like body on the macOS icon grid (824pt body, 100pt margin).
    body_box = (s(100), s(100), s(924), s(924))
    radius = s(186)
    shadow = Image.new("RGBA", canvas.size, (0, 0, 0, 0))
    ImageDraw.Draw(shadow).rounded_rectangle((body_box[0], body_box[1] + s(12), body_box[2], body_box[3] + s(12)), radius, fill=(0, 0, 0, 90))
    canvas.alpha_composite(shadow.filter(ImageFilter.GaussianBlur(s(18))))

    mask = Image.new("L", canvas.size, 0)
    ImageDraw.Draw(mask).rounded_rectangle(body_box, radius, fill=255)
    background = vertical_gradient(canvas.size, (76, 110, 245), (24, 34, 104)).convert("RGBA")
    highlight = Image.new("RGBA", canvas.size, (0, 0, 0, 0))
    ImageDraw.Draw(highlight).ellipse((s(-60), s(-420), s(1084), s(480)), fill=(255, 255, 255, 30))
    background.alpha_composite(highlight.filter(ImageFilter.GaussianBlur(s(140))))
    canvas.paste(background, (0, 0), mask)

    # Shield with a soft drop shadow.
    outline = shield()
    shield_shadow = Image.new("RGBA", canvas.size, (0, 0, 0, 0))
    ImageDraw.Draw(shield_shadow).polygon([(x, y + s(20)) for x, y in outline], fill=(8, 12, 48, 110))
    canvas.alpha_composite(shield_shadow.filter(ImageFilter.GaussianBlur(s(22))))
    shield_fill = vertical_gradient(canvas.size, (255, 255, 255), (220, 228, 255)).convert("RGBA")
    shield_mask = Image.new("L", canvas.size, 0)
    ImageDraw.Draw(shield_mask).polygon(outline, fill=255)
    canvas.paste(shield_fill, (0, 0), shield_mask)

    # Terminal prompt ">_" inside the shield.
    ink = (52, 80, 214, 255)
    draw = ImageDraw.Draw(canvas)
    stroke = s(50)
    chevron = [(s(404), s(438)), (s(510), s(524)), (s(404), s(610))]
    draw.line(chevron, fill=ink, width=stroke, joint="curve")
    for x, y in (chevron[0], chevron[2]):
        draw.ellipse((x - stroke / 2, y - stroke / 2, x + stroke / 2, y + stroke / 2), fill=ink)
    draw.rounded_rectangle((s(540), s(588), s(640), s(632)), s(22), fill=ink)

    out = Path(__file__).resolve().parent.parent / "packaging" / "AppIcon.png"
    canvas.resize((1024, 1024), Image.LANCZOS).save(out)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
