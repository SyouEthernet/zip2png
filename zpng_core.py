#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
zpng_core.py — ZPNG/1.1 核心库：文件/文字/PNG 三态互转（与网页/CLI 完全兼容）
依赖：pip install pillow cryptography piexif

公开函数（供 CLI 或你自己调用）：
- make_blob(data: bytes, with_sha256: bool, password: str|None) -> bytes
- parse_blob(stream: bytes, password: str|None) -> tuple[bytes, int]
- choose_layout(total_bytes: int, req_width: int|None, min_row_bytes=256, max_row_bytes=8192) -> (row_bytes, w, h)
- blob_to_png(blob: bytes, out_path: str, ..., 元数据...) -> None
- png_to_blob(in_path: str) -> tuple[bytes, int]
- file_to_png(...), png_to_file(...), file_to_text(...), text_to_file(...), png_to_text(...), text_to_png(...)

规范：MAGIC="ZPNG"; FLAGS bit0=SHA256, bit1=ENCRYPTED;
加密：scrypt(2^14,8,1) + AES-256-GCM；AAD = MAGIC||FLAGS||LEN_BE||SALT||NONCE
PNG：1bit 灰度，逐行 MSB→LSB，Filter=0（保存时交给 Pillow，但我们按像素显式展开/回收，规避位序差异）
元数据：优先写 PNG 文本 iTXt；可选尝试 eXIf（若 Pillow 版本支持）
"""

from __future__ import annotations
import base64
import hashlib
import math
import os
import struct
from datetime import datetime
from typing import Optional, Tuple

from PIL import Image
from PIL.PngImagePlugin import PngInfo

# 加密
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False

# eXIf
try:
    import piexif
    HAVE_PIEXIF = True
except Exception:
    HAVE_PIEXIF = False

MAGIC = b"ZPNG"
FLAG_SHA256 = 1       # bit0
FLAG_ENCRYPTED = 2    # bit1

ARMOR_BEGIN = "-----BEGIN ZPNG-ARMOR-----"
ARMOR_END   = "-----END ZPNG-ARMOR-----"

# -------- LUT：字节->8像素(0/255)，以及字节按位反转（用于极端兼容回退） --------
def _rev_byte(n: int) -> int:
    r = 0
    for i in range(8):
        r = (r << 1) | ((n >> i) & 1)
    return r
_BIT_LUT = [bytes([255 if (b & (1 << (7 - i))) else 0 for i in range(8)]) for b in range(256)]
_BREV_TABLE = bytes(_rev_byte(i) for i in range(256))

# ------------------- KDF -------------------
def derive_key(password: str, salt: bytes) -> bytes:
    """scrypt KDF -> 32B key (AES-256)"""
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=1<<14, r=8, p=1, dklen=32)

# ------------------- Blob 编解码 -------------------
def make_blob(data: bytes, with_sha256: bool=False, password: Optional[str]=None) -> bytes:
    """
    构建 ZPNG/1.1 blob（可选 SHA-256，口令加密 AES-GCM）
    """
    flags = 0
    if with_sha256:
        flags |= FLAG_SHA256
    if password:
        if not HAVE_CRYPTO:
            raise RuntimeError("缺少 cryptography，请先 pip install cryptography")
        flags |= FLAG_ENCRYPTED

    len_be = struct.pack(">Q", len(data))
    head = MAGIC + bytes([flags]) + len_be

    if flags & FLAG_ENCRYPTED:
        salt  = os.urandom(16)
        nonce = os.urandom(12)
        key   = derive_key(password, salt)
        inner = (hashlib.sha256(data).digest() + data) if (flags & FLAG_SHA256) else data
        aad   = head + salt + nonce
        ct    = AESGCM(key).encrypt(nonce, inner, aad)  # CT||TAG(16)
        return head + salt + nonce + ct
    else:
        extra = hashlib.sha256(data).digest() if (flags & FLAG_SHA256) else b""
        return head + extra + data

def parse_blob(stream: bytes, password: Optional[str]=None) -> Tuple[bytes, int]:
    """
    解析 ZPNG/1.1 blob；返回 (payload_bytes, consumed_length)
    若加密需口令；若带校验会验真；否则按头内 LEN 提取。
    """
    if len(stream) < 13:
        raise RuntimeError("数据不足以包含头部")
    if stream[:4] != MAGIC:
        raise RuntimeError("MAGIC 不匹配：不是 ZPNG blob")

    flags = stream[4]
    payload_len = struct.unpack(">Q", stream[5:13])[0]
    off = 13

    if flags & FLAG_ENCRYPTED:
        if not HAVE_CRYPTO:
            raise RuntimeError("缺少 cryptography，无法解密")
        if len(stream) < off + 28:
            raise RuntimeError("数据不足（SALT/NONCE）")
        salt  = stream[off:off+16]
        nonce = stream[off+16:off+28]
        off  += 28
        inner_len = payload_len + (32 if (flags & FLAG_SHA256) else 0)
        enc_len   = inner_len + 16
        if len(stream) < off + enc_len:
            raise RuntimeError("密文不足（数据被截断）")
        if not password:
            raise RuntimeError("此 blob 启用了加密，需要口令")
        key = derive_key(password, salt)
        aad = MAGIC + bytes([flags]) + struct.pack(">Q", payload_len) + salt + nonce
        try:
            inner = AESGCM(key).decrypt(nonce, stream[off:off+enc_len], aad)
        except Exception:
            raise RuntimeError("解密失败：口令错误或数据损坏")
        if flags & FLAG_SHA256:
            expect = inner[:32]; payload = inner[32:]
            if hashlib.sha256(payload).digest() != expect:
                raise RuntimeError("SHA-256 校验失败：内容已被修改")
        else:
            payload = inner
        if len(payload) != payload_len:
            raise RuntimeError("长度不符：解密结果与头记录不一致")
        return payload, off + enc_len
    else:
        if flags & FLAG_SHA256:
            if len(stream) < off + 32:
                raise RuntimeError("数据不足（SHA-256）")
            expect = stream[off:off+32]
            off += 32
        else:
            expect = None
        if len(stream) < off + payload_len:
            raise RuntimeError("数据不足（有效负载被截断）")
        payload = stream[off:off+payload_len]
        if expect and hashlib.sha256(payload).digest() != expect:
            raise RuntimeError("SHA-256 校验失败")
        return payload, off + payload_len

# ------------------- 文字装甲 -------------------
def armor_blob(blob: bytes, wrap: int=76, armor: bool=True) -> str:
    b64 = base64.b64encode(blob).decode("ascii")
    if wrap and wrap > 0:
        lines = "\n".join(b64[i:i+wrap] for i in range(0, len(b64), wrap))
    else:
        lines = b64
    return f"{ARMOR_BEGIN}\n{lines}\n{ARMOR_END}\n" if armor else (lines + "\n")

def dearmor_to_blob(text: str) -> bytes:
    s = text.strip()
    import re
    m = re.search(r"-----BEGIN .*?-----\s*(.*?)\s*-----END .*?-----", s, flags=re.S)
    body = (m.group(1) if m else s)
    body = "".join(ch for ch in body if ch.isalnum() or ch in "+/=\r\n").replace("\r","").replace("\n","")
    return base64.b64decode(body)

# ------------------- PNG 元数据 -------------------
def _normalize_datetime(s: Optional[str]):
    if not s:
        return None, None
    s = s.strip()
    for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s, fmt)
            if fmt == "%Y-%m-%d":
                dt = dt.replace(hour=0, minute=0, second=0)
            exif_fmt = dt.strftime("%Y:%m:%d %H:%M:%S")
            text_fmt = dt.strftime("%Y-%m-%d %H:%M:%S")
            return exif_fmt, text_fmt
        except Exception:
            pass
    return None, s

def build_png_textinfo(meta: dict, flags_str: str, src_basename: str) -> PngInfo:
    info = PngInfo()
    def add(k, v):
        if v is None:
            return
        info.add_itxt(k, str(v), lang="", tkey=k)
    add("Title", meta.get("title"))
    add("Author", meta.get("artist"))
    add("Description", meta.get("comment"))
    add("Software", meta.get("software") or "ZPNG")
    add("Creation Time", meta.get("text_datetime"))
    add("Make", meta.get("camera_make"))
    add("Model", meta.get("camera_model"))
    add("Camera Serial Number", meta.get("serial"))
    add("Location", meta.get("location"))
    add("X-Original-Filename", src_basename)
    add("X-ZPNG-Flags", flags_str)
    return info

def build_exif_bytes(meta: dict):
    if not HAVE_PIEXIF:
        return None
    zeroth, exif = {}, {}
    try:
        if meta.get("camera_make"):
            zeroth[piexif.ImageIFD.Make] = meta["camera_make"]
        if meta.get("camera_model"):
            zeroth[piexif.ImageIFD.Model] = meta["camera_model"]
        if meta.get("artist"):
            zeroth[piexif.ImageIFD.Artist] = meta["artist"]
        if meta.get("exif_datetime"):
            dt = meta["exif_datetime"]
            zeroth[piexif.ImageIFD.DateTime] = dt
            exif[piexif.ExifIFD.DateTimeOriginal] = dt
        return piexif.dump({"0th": zeroth, "Exif": exif})
    except Exception:
        return None

# ------------------- 位图布局 -------------------
def choose_layout(total_bytes: int, req_width: Optional[int]=None,
                  min_row_bytes: int=256, max_row_bytes: int=8192):
    if req_width and req_width > 0:
        row_bytes = (req_width + 7) // 8
    else:
        target = int(math.sqrt(total_bytes)) or 1
        row_bytes = max(min_row_bytes, min(max_row_bytes, target))
    width = row_bytes * 8
    height = (total_bytes + row_bytes - 1) // row_bytes
    return row_bytes, width, height

# ------------------- PNG 写入/读取（显式位序，完全与 HTML 一致） -------------------
def _expand_bitpacked_to_L(packed: bytes, w: int, h: int, row_bytes: int) -> bytes:
    """将按 MSB->LSB 打包的位流展开为 8bit 灰度（0/255）像素"""
    out = bytearray(w * h)
    for y in range(h):
        dst = y * w
        src = y * row_bytes
        full_bytes = w // 8
        rem_bits = w & 7
        for xb in range(full_bytes):
            out[dst:dst+8] = _BIT_LUT[packed[src + xb]]
            dst += 8
        if rem_bits:
            lut = _BIT_LUT[packed[src + full_bytes]]
            out[dst:dst+rem_bits] = lut[:rem_bits]
    return bytes(out)

def blob_to_png(blob: bytes, out_path: str, req_width: Optional[int]=None,
                min_row_bytes: int=256, max_row_bytes: int=8192,
                # 元数据
                title=None, artist=None, comment=None, software=None,
                shoot_datetime=None, camera_make=None, camera_model=None,
                serial=None, location=None, embed_exif: bool=True, src_basename="payload"):
    """
    写 PNG 时不再依赖 Pillow 的原始位序接口，改为：
      bit-packed(ZPNG) -> 展开为 L(8bit, 0/255) -> point 阈值 -> '1' 模式 -> 保存
    从而在所有平台得到完全一致的像素映射（MSB->LSB）。
    """
    total = len(blob)
    row_bytes, w, h = choose_layout(total, req_width, min_row_bytes, max_row_bytes)

    # 将 blob 放入位流平面（剩余填 0）
    packed = bytearray(h * row_bytes)
    packed[:total] = blob

    # 展开为 8bit 灰度，再阈值到 '1'（无抖动）
    L_bytes = _expand_bitpacked_to_L(packed, w, h, row_bytes)
    img_L = Image.frombytes("L", (w, h), L_bytes)
    img_1 = img_L.point(lambda p: 255 if p >= 128 else 0, "1")

    flags = blob[4] if len(blob) >= 5 else 0
    flags_str = ("ENC+" if (flags & FLAG_ENCRYPTED) else "") + ("SHA256" if (flags & FLAG_SHA256) else "0")

    exif_dt, text_dt = _normalize_datetime(shoot_datetime) if shoot_datetime else (None, None)
    meta = dict(title=title, artist=artist, comment=comment, software=software or "ZPNG",
                camera_make=camera_make, camera_model=camera_model, serial=serial, location=location,
                exif_datetime=exif_dt, text_datetime=text_dt)
    pnginfo = build_png_textinfo(meta, flags_str, src_basename)
    exif_bytes = build_exif_bytes(meta) if embed_exif else None

    try:
        if exif_bytes:
            img_1.save(out_path, format="PNG", pnginfo=pnginfo, exif=exif_bytes,
                       optimize=False, compress_level=9)
        else:
            img_1.save(out_path, format="PNG", pnginfo=pnginfo,
                       optimize=False, compress_level=9)
    except Exception:
        img_1.save(out_path, format="PNG", pnginfo=pnginfo, optimize=False, compress_level=9)

def png_to_blob(in_path: str) -> Tuple[bytes, int]:
    """
    读取 PNG 时也不信任 Pillow 的 1bit 原始位序：
      PNG -> L(8bit) -> 阈值 >=128 为 1 -> 按 MSB->LSB 打包为位流
    如首次打包后 MAGIC 不对，尝试逐字节 bit-reverse 作为极端兼容回退（不影响本项目的 HTML/CLI 互通）。
    """
    im = Image.open(in_path).convert("L")
    w, h = im.size
    pix = im.tobytes()  # 每像素 0..255
    row_bytes = (w + 7) // 8
    packed = bytearray(row_bytes * h)
    for y in range(h):
        base = y * w
        row_off = y * row_bytes
        for x in range(w):
            bit = 1 if pix[base + x] >= 128 else 0
            byte_index = row_off + (x >> 3)
            bit_pos = 7 - (x & 7)  # MSB 左对齐
            if bit:
                packed[byte_index] |= (1 << bit_pos)

    stream = bytes(packed)

    # 规范裁剪：取到完整一个 ZPNG blob 的最小长度
    if len(stream) < 13 or stream[:4] != MAGIC:
        # 极端回退：逐字节 bit-reverse 再试（兼容历史/第三方错误位序）
        rev = bytes(_BREV_TABLE[b] for b in stream)
        if not (len(rev) >= 13 and rev[:4] == MAGIC):
            raise RuntimeError("PNG 中找不到合法的 ZPNG blob（MAGIC 不对）")
        stream = rev

    flags = stream[4]
    payload_len = struct.unpack(">Q", stream[5:13])[0]
    off = 13
    if flags & FLAG_ENCRYPTED:
        need = off + 28 + payload_len + (32 if (flags & FLAG_SHA256) else 0) + 16
    else:
        need = off + (32 if (flags & FLAG_SHA256) else 0) + payload_len
    if len(stream) < need:
        raise RuntimeError("PNG 中的 blob 不完整")
    return stream[:need], need

# ------------------- 高层便捷函数 -------------------
def file_to_png(in_path, out_path, width=None, with_sha256=False, password=None,
                min_row_bytes=256, max_row_bytes=8192,
                title=None, artist=None, comment=None, software=None,
                shoot_datetime=None, camera_make=None, camera_model=None,
                serial=None, location=None, embed_exif=True):
    with open(in_path, "rb") as f:
        data = f.read()
    blob = make_blob(data, with_sha256=with_sha256, password=password)
    blob_to_png(blob, out_path, req_width=width,
                min_row_bytes=min_row_bytes, max_row_bytes=max_row_bytes,
                title=title, artist=artist, comment=comment, software=software,
                shoot_datetime=shoot_datetime, camera_make=camera_make, camera_model=camera_model,
                serial=serial, location=location, embed_exif=embed_exif, src_basename=os.path.basename(in_path))

def png_to_file(in_path, out_path, password=None):
    blob, _ = png_to_blob(in_path)
    payload, _ = parse_blob(blob, password=password)
    with open(out_path, "wb") as f:
        f.write(payload)

def file_to_text(in_path, out_path, with_sha256=False, password=None, armor=True, wrap=76):
    with open(in_path, "rb") as f:
        data = f.read()
    blob = make_blob(data, with_sha256=with_sha256, password=password)
    txt = armor_blob(blob, wrap=wrap, armor=armor)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(txt)

def text_to_file(in_path, out_path, password=None):
    with open(in_path, "r", encoding="utf-8") as f:
        txt = f.read()
    blob = dearmor_to_blob(txt)
    payload, _ = parse_blob(blob, password=password)
    with open(out_path, "wb") as f:
        f.write(payload)

def png_to_text(in_path, out_path, armor=True, wrap=76):
    blob, _ = png_to_blob(in_path)
    txt = armor_blob(blob, wrap=wrap, armor=armor)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(txt)

def text_to_png(in_path, out_path, width=None,
                min_row_bytes=256, max_row_bytes=8192,
                title=None, artist=None, comment=None, software=None,
                shoot_datetime=None, camera_make=None, camera_model=None,
                serial=None, location=None, embed_exif=True, src_name="from-text"):
    with open(in_path, "r", encoding="utf-8") as f:
        txt = f.read()
    blob = dearmor_to_blob(txt)
    blob_to_png(blob, out_path, req_width=width,
                min_row_bytes=min_row_bytes, max_row_bytes=max_row_bytes,
                title=title, artist=artist, comment=comment, software=software,
                shoot_datetime=shoot_datetime, camera_make=camera_make, camera_model=camera_model,
                serial=serial, location=location, embed_exif=embed_exif, src_basename=src_name)
