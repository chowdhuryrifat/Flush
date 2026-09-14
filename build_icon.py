#!/usr/bin/env python3
"""
build_icon.py — generates the Minecraft-style app icon (creeper-faced USB stick).
Outputs icon.png and icon.ico for PyInstaller + desktop use.
"""

from pathlib import Path

from PIL import Image, ImageDraw

HERE = Path(__file__).resolve().parent
OUT_PNG = HERE / "icon.png"
OUT_ICO = HERE / "icon.ico"

# 8x8 source grid of the creeper face.
#  H = head (dark green), F = face (light green), K = features (black)
CREEPER_GRID = [
    "HHHHHHHH",
    "HFFFFFFH",
    "HFFFFFFH",
    "HFKKFKFH",
    "HFKKFKFH",
    "HFFFFFFH",
    "HKFFFFKH",
    "HHKKKKHH",
]

PALETTE = {
    "H": (0x5A, 0x9A, 0x3D),  # dark green head
    "F": (0x7C, 0xBD, 0x6B),  # grass-green face
    "K": (0x11, 0x11, 0x11),  # near-black features
}


def build_icon_art(size=16):
    """Render the creeper face into a (size x size) RGBA surface."""
    scale = size // 8
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    for y, row in enumerate(CREEPER_GRID):
        for x, ch in enumerate(row):
            color = PALETTE[ch]
            draw.rectangle(
                [x * scale, y * scale, (x + 1) * scale - 1, (y + 1) * scale - 1],
                fill=color + (255,),
            )
    return img


def composite_with_usb(face: Image.Image, size=16):
    """Place the creeper face on a pixelated USB-stick chassis."""
    scale = size // 16
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # USB metal connector at top (rows 0-3) -- light silver with a slit
    metal_light = (0xC9, 0xD4, 0xDF, 255)
    metal_shade = (0x93, 0xA4, 0xB6, 255)
    slit = (0x2E, 0x33, 0x3B, 255)

    connector_top = 0
    connector_h = 3
    draw.rectangle(
        [4 * scale, connector_top * scale,
         (16 - 4) * scale - 1, (connector_top + connector_h) * scale - 1],
        fill=metal_light,
    )
    # two side prongs
    prong_w = 2
    for px in (4, 16 - 4 - prong_w):
        draw.rectangle(
            [px * scale, connector_top * scale,
             (px + prong_w) * scale - 1, (connector_top + connector_h) * scale - 1],
            fill=metal_shade,
        )
    # center slit
    draw.rectangle(
        [7 * scale, (connector_top + 1) * scale,
         9 * scale - 1, (connector_top + connector_h) * scale - 1],
        fill=slit,
    )

    # Body (rows 4-15): dark chassis frame, creeper face inset
    body_top = 4
    chassis = (0x3B, 0x5E, 0x2F, 255)  # dark olive
    draw.rectangle(
        [0, body_top * scale, size - 1, size - 1],
        fill=chassis,
    )
    # inset the 8x8 face into the body (rows 4-15 => 12 rows, face is 16.. but fit)
    # Scale creeper to 12x12 and center it
    face_small = face.resize((12 * scale, 12 * scale), Image.NEAREST)
    x0 = (size - 12 * scale) // 2
    y0 = body_top * scale + (size - body_top * scale - 12 * scale) // 2
    img.paste(face_small, (x0, y0), face_small)

    return img


def main():
    base = build_icon_art(16)

    # 16x16 composite for the main icon (256 final render)
    art16 = composite_with_usb(base, 16)
    final = art16.resize((256, 256), Image.NEAREST)
    final.save(OUT_PNG)

    # Generate .ico with standard sizes
    final.save(
        OUT_ICO,
        format="ICO",
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )
    print(f"Wrote {OUT_PNG} and {OUT_ICO}")


if __name__ == "__main__":
    main()