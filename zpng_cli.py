#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
zpng_cli.py — ZPNG/1.1 命令行工具（与网页/核心库完全一致）
依赖：zpng_core.py 在同目录；pip install pillow cryptography piexif
"""

import argparse
import os
from zpng_core import (
    file_to_png, png_to_file, file_to_text, text_to_file,
    png_to_text, text_to_png
)

def main():
    p = argparse.ArgumentParser(description="ZPNG/1.1：文件/文字/1bit PNG 三态互转（可选AES-GCM口令；SHA-256；PNG写iTXt）")
    sub = p.add_subparsers(dest="cmd", required=True)

    # 文件 -> PNG
    pe = sub.add_parser("encode", help="文件 -> 1bit PNG")
    pe.add_argument("input")
    pe.add_argument("output")
    pe.add_argument("--width", type=int, default=0, help="图像宽度（像素，凑到8倍数；默认自动）")
    pe.add_argument("--checksum", action="store_true", help="附加 SHA-256 校验")
    pe.add_argument("--password", type=str, default=None, help="口令（AES-256-GCM 加密）")
    pe.add_argument("--min-row-bytes", type=int, default=256)
    pe.add_argument("--max-row-bytes", type=int, default=8192)
    # 元数据（与 HTML 字段一致）
    pe.add_argument("--title", type=str, default=None)
    pe.add_argument("--artist", type=str, default=None)
    pe.add_argument("--comment", type=str, default=None)
    pe.add_argument("--software", type=str, default="ZPNG")
    pe.add_argument("--shoot-datetime", type=str, default=None)
    pe.add_argument("--camera-make", type=str, default=None)
    pe.add_argument("--camera-model", type=str, default=None)
    pe.add_argument("--serial", type=str, default=None)
    pe.add_argument("--location", type=str, default=None)
    pe.add_argument("--no-exif", action="store_true", help="不尝试写 PNG eXIf，仅写 iTXt")

    # PNG -> 文件
    pd = sub.add_parser("decode", help="1bit PNG -> 文件")
    pd.add_argument("input")
    pd.add_argument("output")
    pd.add_argument("--password", type=str, default=None, help="若加密需口令")

    # 文件 -> 文字
    pt = sub.add_parser("to-text", help="文件 -> 文字装甲/Base64")
    pt.add_argument("input")
    pt.add_argument("output")
    pt.add_argument("--checksum", action="store_true")
    pt.add_argument("--password", type=str, default=None)
    pt.add_argument("--no-armor", action="store_true", help="输出纯 Base64（无头尾）")
    pt.add_argument("--wrap", type=int, default=76, help="每行宽，0 表示不换行")

    # 文字 -> 文件
    pf = sub.add_parser("from-text", help="文字装甲/Base64 -> 文件")
    pf.add_argument("input")
    pf.add_argument("output")
    pf.add_argument("--password", type=str, default=None)

    # PNG -> 文字
    pxt = sub.add_parser("png-to-text", help="PNG -> 文字装甲（不解密）")
    pxt.add_argument("input")
    pxt.add_argument("output")
    pxt.add_argument("--no-armor", action="store_true")
    pxt.add_argument("--wrap", type=int, default=76)

    # 文字 -> PNG
    ptx = sub.add_parser("text-to-png", help="文字装甲/Base64 -> 1bit PNG")
    ptx.add_argument("input")
    ptx.add_argument("output")
    ptx.add_argument("--width", type=int, default=0)
    ptx.add_argument("--min-row-bytes", type=int, default=256)
    ptx.add_argument("--max-row-bytes", type=int, default=8192)
    # 元数据（与 HTML 字段一致）
    ptx.add_argument("--title", type=str, default=None)
    ptx.add_argument("--artist", type=str, default=None)
    ptx.add_argument("--comment", type=str, default=None)
    ptx.add_argument("--software", type=str, default="ZPNG")
    ptx.add_argument("--shoot-datetime", type=str, default=None)
    ptx.add_argument("--camera-make", type=str, default=None)
    ptx.add_argument("--camera-model", type=str, default=None)
    ptx.add_argument("--serial", type=str, default=None)
    ptx.add_argument("--location", type=str, default=None)
    ptx.add_argument("--no-exif", action="store_true")

    args = p.parse_args()
    if args.cmd == "encode":
        file_to_png(
            args.input, args.output,
            width=args.width or None,
            with_sha256=args.checksum,
            password=args.password,
            min_row_bytes=args.min_row_bytes, max_row_bytes=args.max_row_bytes,
            title=args.title, artist=args.artist, comment=args.comment, software=args.software,
            shoot_datetime=args.shoot_datetime, camera_make=args.camera_make, camera_model=args.camera_model,
            serial=args.serial, location=args.location, embed_exif=not args.no_exif
        )
        print(f"OK: 写出 {args.output}")
    elif args.cmd == "decode":
        png_to_file(args.input, args.output, password=args.password)
        print(f"OK: 解码到 {args.output}")
    elif args.cmd == "to-text":
        file_to_text(args.input, args.output, with_sha256=args.checksum, password=args.password,
                     armor=not args.no_armor, wrap=args.wrap)
        print(f"OK: 写出 {args.output}")
    elif args.cmd == "from-text":
        text_to_file(args.input, args.output, password=args.password)
        print(f"OK: 解码到 {args.output}")
    elif args.cmd == "png-to-text":
        png_to_text(args.input, args.output, armor=not args.no_armor, wrap=args.wrap)
        print(f"OK: 写出 {args.output}")
    elif args.cmd == "text-to-png":
        text_to_png(
            args.input, args.output, width=args.width or None,
            min_row_bytes=args.min_row_bytes, max_row_bytes=args.max_row_bytes,
            title=args.title, artist=args.artist, comment=args.comment, software=args.software,
            shoot_datetime=args.shoot_datetime, camera_make=args.camera_make, camera_model=args.camera_model,
            serial=args.serial, location=args.location, embed_exif=not args.no_exif,
            src_name=os.path.basename(args.input)
        )
        print(f"OK: 写出 {args.output}")
    else:
        p.error("未知命令")

if __name__ == "__main__":
    main()
