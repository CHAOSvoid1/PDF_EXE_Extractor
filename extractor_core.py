from __future__ import annotations

import io
import logging
import os
import re
import struct
import zlib
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

LogFn = Callable[[str], None]


class ExtractionError(RuntimeError):
    pass


@dataclass
class XRefRevision:
    kind: str
    stored_offset: int
    logical_offset: int
    objno: int | None
    entries: dict[int, tuple[int, int, int]]
    dictionary: bytes


@dataclass
class ExtractionResult:
    input_path: Path
    output_path: Path
    object_count: int
    page_hint: int | None
    xref_revisions: int
    mapping_deltas: tuple[int, ...]
    warnings: list[str]


def _noop(_: str) -> None:
    pass


def find_pe_overlay(data: bytes) -> int:
    """Return the first byte after the PE sections, without executing the file."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ExtractionError("输入文件不是有效的 Windows PE/EXE 文件")
    peoff = struct.unpack_from("<I", data, 0x3C)[0]
    if peoff + 24 > len(data) or data[peoff:peoff + 4] != b"PE\0\0":
        raise ExtractionError("EXE 的 PE 头损坏或无法识别")
    nsec = struct.unpack_from("<H", data, peoff + 6)[0]
    opt_size = struct.unpack_from("<H", data, peoff + 20)[0]
    sec_table = peoff + 24 + opt_size
    ends: list[int] = []
    for i in range(nsec):
        off = sec_table + i * 40
        if off + 40 > len(data):
            raise ExtractionError("EXE 节表不完整")
        raw_size = struct.unpack_from("<I", data, off + 16)[0]
        raw_ptr = struct.unpack_from("<I", data, off + 20)[0]
        ends.append(raw_ptr + raw_size)
    if not ends:
        raise ExtractionError("EXE 中没有可识别的 PE 节")
    overlay = max(ends)
    if overlay >= len(data):
        raise ExtractionError("EXE 中没有附加数据，未发现嵌入式 PDF")
    return overlay


def repair_flate(data: bytes) -> tuple[bytes, bytes]:
    """Repair the two-byte zlib header commonly altered by this wrapper family."""
    if not data:
        raise ExtractionError("遇到空的 Flate 压缩流")
    # First accept an already-valid stream.
    try:
        return data, zlib.decompress(data)
    except zlib.error:
        pass
    if len(data) >= 2:
        for header in (b"\x78\x9c", b"\x78\xda", b"\x78\x5e", b"\x78\x01"):
            candidate = header + data[2:]
            try:
                return candidate, zlib.decompress(candidate)
            except zlib.error:
                continue
    try:
        decoded = zlib.decompress(data, -15)
        return zlib.compress(decoded), decoded
    except zlib.error as exc:
        raise ExtractionError(f"无法修复 Flate 压缩流，开头为 {data[:8].hex()}") from exc


def png_predictor_decode(raw: bytes, columns: int, bpp: int = 1) -> bytes:
    if columns <= 0:
        return raw
    rows: list[bytes] = []
    prev = bytearray(columns)
    i = 0
    while i < len(raw):
        f = raw[i]
        i += 1
        cur = bytearray(raw[i:i + columns])
        i += columns
        if len(cur) != columns:
            raise ExtractionError("PNG Predictor 数据行被截断")
        out = bytearray(columns)
        for j, x in enumerate(cur):
            a = out[j - bpp] if j >= bpp else 0
            up = prev[j]
            ul = prev[j - bpp] if j >= bpp else 0
            if f == 0:
                val = x
            elif f == 1:
                val = (x + a) & 0xFF
            elif f == 2:
                val = (x + up) & 0xFF
            elif f == 3:
                val = (x + ((a + up) // 2)) & 0xFF
            elif f == 4:
                p = a + up - ul
                pa, pb, pc = abs(p - a), abs(p - up), abs(p - ul)
                pr = a if pa <= pb and pa <= pc else (up if pb <= pc else ul)
                val = (x + pr) & 0xFF
            else:
                raise ExtractionError(f"不支持的 PNG Predictor 过滤器 {f}")
            out[j] = val
        rows.append(bytes(out))
        prev = out
    return b"".join(rows)


def _stream_bounds(buf: bytes, object_start: int, search_limit: int | None = None) -> tuple[bytes, int, int, int]:
    """Return dict bytes, data start, declared length, stream keyword offset."""
    end = len(buf) if search_limit is None else min(len(buf), search_limit)
    sm = buf.find(b"stream", object_start, end)
    if sm < 0:
        raise ExtractionError("对象中找不到 stream 关键字")
    dict_bytes = buf[object_start:sm]
    lm = re.search(rb"/Length\s+(\d+)\b", dict_bytes)
    if not lm:
        raise ExtractionError("当前版本暂不支持间接 /Length 的该对象")
    length = int(lm.group(1))
    ds = sm + 6
    if buf[ds:ds + 2] == b"\r\n":
        ds += 2
    elif buf[ds:ds + 1] in (b"\r", b"\n"):
        ds += 1
    return dict_bytes, ds, length, sm


def scan_object_headers(overlay: bytes) -> dict[tuple[int, int], list[int]]:
    result: dict[tuple[int, int], list[int]] = defaultdict(list)
    pat = re.compile(rb"(?<!\d)(\d+)\s+(\d+)\s+obj\b")
    for m in pat.finditer(overlay):
        result[(int(m.group(1)), int(m.group(2)))].append(m.start())
    return result


def parse_xref_stream_at(overlay: bytes, stored_offset: int) -> XRefRevision:
    hm = re.match(rb"(\d+)\s+(\d+)\s+obj\b", overlay[stored_offset:stored_offset + 80])
    if not hm:
        raise ExtractionError("XRef 流对象头无法识别")
    objno = int(hm.group(1))
    sm = overlay.find(b"stream", stored_offset, min(len(overlay), stored_offset + 20000))
    if sm < 0:
        raise ExtractionError("XRef 流缺少 stream")
    dict_bytes = overlay[stored_offset + hm.end():sm]
    lm = re.search(rb"/Length\s+(\d+)\b", dict_bytes)
    if not lm:
        raise ExtractionError("XRef 流没有直接 Length")
    length = int(lm.group(1))
    ds = sm + 6
    if overlay[ds:ds + 2] == b"\r\n":
        ds += 2
    elif overlay[ds:ds + 1] in (b"\r", b"\n"):
        ds += 1
    encoded = overlay[ds:ds + length]
    _, decoded = repair_flate(encoded)

    pm = re.search(rb"/Predictor\s+(\d+)", dict_bytes)
    if pm and int(pm.group(1)) >= 10:
        cm = re.search(rb"/Columns\s+(\d+)", dict_bytes)
        columns = int(cm.group(1)) if cm else 1
        decoded = png_predictor_decode(decoded, columns)

    wm = re.search(rb"/W\s*\[([^]]+)\]", dict_bytes)
    if not wm:
        raise ExtractionError("XRef 流缺少 W 数组")
    widths = [int(x) for x in re.findall(rb"\d+", wm.group(1))]
    if len(widths) != 3:
        raise ExtractionError("仅支持三字段 XRef 流")

    im = re.search(rb"/Index\s*\[([^]]+)\]", dict_bytes)
    if im:
        nums = [int(x) for x in re.findall(rb"\d+", im.group(1))]
        ranges = list(zip(nums[::2], nums[1::2]))
    else:
        size_m = re.search(rb"/Size\s+(\d+)", dict_bytes)
        if not size_m:
            raise ExtractionError("XRef 流缺少 Size")
        ranges = [(0, int(size_m.group(1)))]

    row_size = sum(widths)
    expected = sum(c for _, c in ranges) * row_size
    if len(decoded) < expected:
        raise ExtractionError("XRef 流解压长度不足")
    entries: dict[int, tuple[int, int, int]] = {}
    k = 0
    for first, count in ranges:
        for no in range(first, first + count):
            row = decoded[k:k + row_size]
            k += row_size
            vals: list[int] = []
            p = 0
            for wi, width in enumerate(widths):
                if width == 0:
                    vals.append(1 if wi == 0 else 0)
                else:
                    vals.append(int.from_bytes(row[p:p + width], "big"))
                    p += width
            entries[no] = (vals[0], vals[1], vals[2])

    self_entry = entries.get(objno)
    logical_offset = self_entry[1] if self_entry and self_entry[0] == 1 else -1
    return XRefRevision("stream", stored_offset, logical_offset, objno, entries, dict_bytes)


def find_xref_streams(overlay: bytes, headers: dict[tuple[int, int], list[int]]) -> list[XRefRevision]:
    revisions: list[XRefRevision] = []
    for (objno, gen), positions in headers.items():
        if gen != 0:
            continue
        for pos in positions:
            # XRef dictionaries are small; don't inspect arbitrary huge objects deeply.
            probe = overlay[pos:min(len(overlay), pos + 4096)]
            stream_at = probe.find(b"stream")
            if stream_at < 0:
                continue
            dictionary = probe[:stream_at]
            if not (re.search(rb"/Type\s*/XRef\b", dictionary) or b"/Type/XRef" in dictionary):
                continue
            try:
                revisions.append(parse_xref_stream_at(overlay, pos))
            except ExtractionError:
                continue
    # Deduplicate by stored position.
    unique = {r.stored_offset: r for r in revisions}
    return list(unique.values())


def find_classic_xrefs(overlay: bytes) -> list[XRefRevision]:
    revisions: list[XRefRevision] = []
    # The table itself remains readable in the wrapper format.
    for m in re.finditer(rb"(?m)^xref\s*(?:\r\n|\r|\n)", overlay):
        pos = m.start()
        cursor = m.end()
        entries: dict[int, tuple[int, int, int]] = {}
        ok = True
        while cursor < len(overlay):
            trailer = re.match(rb"trailer\b", overlay[cursor:cursor + 20])
            if trailer:
                cursor += trailer.end()
                break
            sm = re.match(rb"(\d+)\s+(\d+)\s*(?:\r\n|\r|\n)", overlay[cursor:cursor + 100])
            if not sm:
                ok = False
                break
            first, count = int(sm.group(1)), int(sm.group(2))
            cursor += sm.end()
            for no in range(first, first + count):
                em = re.match(rb"(\d{10})\s+(\d{5})\s+([nf])\s*(?:\r\n|\r|\n)", overlay[cursor:cursor + 40])
                if not em:
                    ok = False
                    break
                typ = 1 if em.group(3) == b"n" else 0
                entries[no] = (typ, int(em.group(1)), int(em.group(2)))
                cursor += em.end()
            if not ok:
                break
        if not ok or not entries:
            continue
        # Capture trailer dictionary until startxref.
        sx = overlay.find(b"startxref", cursor, min(len(overlay), cursor + 4096))
        dictionary = overlay[cursor:sx if sx >= 0 else min(len(overlay), cursor + 4096)]
        logical_offset = -1
        if sx >= 0:
            nm = re.search(rb"startxref\s+(\d+)", overlay[sx:sx + 80])
            if nm:
                logical_offset = int(nm.group(1))
        revisions.append(XRefRevision("classic", pos, logical_offset, None, entries, dictionary))
    return revisions


def _pick_revisions(revisions: list[XRefRevision], log: LogFn) -> list[XRefRevision]:
    if not revisions:
        raise ExtractionError("未找到可解析的 PDF 交叉引用表")
    # Prefer the most complete representation at the same logical offset.
    dedup: dict[tuple[str, int, int | None], XRefRevision] = {}
    for r in revisions:
        key = (r.kind, r.logical_offset, r.objno)
        old = dedup.get(key)
        if old is None or len(r.entries) > len(old.entries):
            dedup[key] = r
    revisions = list(dedup.values())
    # Unknown logical offsets go first, known offsets establish incremental order.
    revisions.sort(key=lambda r: (r.logical_offset < 0, r.logical_offset if r.logical_offset >= 0 else r.stored_offset))
    for r in revisions:
        log(f"发现 {r.kind} XRef：存储偏移 {r.stored_offset}，逻辑偏移 {r.logical_offset}，条目 {len(r.entries)}")
    return revisions


def infer_mapping(
    overlay: bytes,
    entries: dict[int, tuple[int, int, int]],
    headers: dict[tuple[int, int], list[int]],
    log: LogFn,
) -> tuple[tuple[int, ...], dict[int, int]]:
    delta_counter: Counter[int] = Counter()
    candidates_by_obj: dict[int, list[tuple[int, int]]] = {}
    for no, (typ, logical, gen) in entries.items():
        if typ != 1:
            continue
        positions = headers.get((no, gen), [])
        candidates = [(p, p - logical) for p in positions]
        candidates_by_obj[no] = candidates
        for _, delta in candidates:
            delta_counter[delta] += 1
    if not delta_counter:
        raise ExtractionError("无法从对象位置推断 PDF 数据映射")

    type1_count = sum(1 for v in entries.values() if v[0] == 1)
    minimum = max(2, int(type1_count * 0.015))
    major = [(d, c) for d, c in delta_counter.most_common() if c >= minimum]
    if not major:
        major = delta_counter.most_common(2)
    # This wrapper family normally uses one or two rotation deltas. Keep at most three
    # to tolerate an incremental update chunk, but prefer the dominant pair.
    selected = [d for d, _ in major[:3]]
    if len(selected) > 2:
        # Keep the strongest negative and strongest non-negative if both exist.
        neg = next((d for d, _ in major if d < 0), None)
        pos = next((d for d, _ in major if d >= 0), None)
        if neg is not None and pos is not None:
            selected = [pos, neg]
        else:
            selected = selected[:2]
    selected_tuple = tuple(selected)
    log("推断出的数据映射偏移：" + ", ".join(str(x) for x in selected_tuple))

    chosen_positions: dict[int, int] = {}
    selected_set = set(selected_tuple)
    for no, candidates in candidates_by_obj.items():
        exact = [p for p, d in candidates if d in selected_set]
        if len(exact) == 1:
            chosen_positions[no] = exact[0]
        elif len(exact) > 1:
            # Latest object version usually has the largest logical/stored placement.
            logical = entries[no][1]
            chosen_positions[no] = min(exact, key=lambda p: abs((p - logical) - selected_tuple[0]))
        elif candidates:
            # Orphan/update anomalies: choose the candidate closest to a major delta.
            chosen_positions[no] = min(candidates, key=lambda pd: min(abs(pd[1] - d) for d in selected_tuple))[0]
    return selected_tuple, chosen_positions


class LogicalReader:
    def __init__(self, overlay: bytes, deltas: tuple[int, ...]):
        self.overlay = overlay
        self.deltas = deltas
        self.neg = next((d for d in deltas if d < 0), None)
        self.pos = next((d for d in deltas if d >= 0), None)
        self.cut = -self.neg if self.neg is not None else None

    def _delta_for(self, logical_pos: int) -> int:
        if self.neg is not None and self.pos is not None and self.cut is not None:
            return self.pos if logical_pos < self.cut else self.neg
        if len(self.deltas) == 1:
            return self.deltas[0]
        # If only negatives or only positives were observed, choose the first dominant mapping.
        return self.deltas[0]

    def read(self, start: int, length: int) -> bytes:
        out = bytearray()
        pos = start
        remain = length
        while remain > 0:
            delta = self._delta_for(pos)
            take = remain
            if self.cut is not None and self.neg is not None and self.pos is not None and pos < self.cut:
                take = min(take, self.cut - pos)
            stored = pos + delta
            if stored < 0 or stored + take > len(self.overlay):
                raise ExtractionError(
                    f"逻辑范围 {pos}:{pos + take} 映射到 EXE 附加区 {stored}:{stored + take}，超出边界"
                )
            out += self.overlay[stored:stored + take]
            pos += take
            remain -= take
        return bytes(out)


def parse_indirect_logical(
    reader: LogicalReader,
    true_offset: int,
    expected_obj: int,
    warnings: list[str],
) -> tuple[bytes, bytes | None]:
    size = 4096
    while size <= 16_000_000:
        chunk = reader.read(true_offset, size)
        hm = re.match(rb"(\d+)\s+(\d+)\s+obj(?:\r\n|\r|\n|\s)", chunk)
        if not hm:
            raise ExtractionError(f"对象 {expected_obj} 在逻辑偏移 {true_offset} 处没有有效对象头")
        got = int(hm.group(1))
        if got != expected_obj:
            raise ExtractionError(f"XRef 指向对象 {expected_obj}，实际读到对象 {got}")
        body_start = hm.end()
        stream_kw = chunk.find(b"stream", body_start)
        first_endobj = chunk.find(b"endobj", body_start)
        if first_endobj >= 0 and (stream_kw < 0 or first_endobj < stream_kw):
            return chunk[body_start:first_endobj].rstrip(b"\r\n"), None
        if stream_kw >= 0:
            dict_bytes = chunk[body_start:stream_kw]
            lm = re.search(rb"/Length\s+(\d+)\b", dict_bytes)
            if lm:
                length = int(lm.group(1))
                ds = stream_kw + 6
                if chunk[ds:ds + 2] == b"\r\n":
                    ds += 2
                elif chunk[ds:ds + 1] in (b"\r", b"\n"):
                    ds += 1
                need = ds + length + 64
                if need > len(chunk):
                    size = max(size * 2, need)
                    continue
                data = chunk[ds:ds + length]
                repaired = data
                decoded: bytes | None = None
                if b"FlateDecode" in dict_bytes:
                    try:
                        repaired, decoded = repair_flate(data)
                    except ExtractionError as exc:
                        warnings.append(f"对象 {expected_obj} 的 Flate 流未能自动修复：{exc}")
                if len(repaired) != len(data):
                    dict_bytes = re.sub(
                        rb"/Length\s+\d+\b",
                        f"/Length {len(repaired)}".encode(),
                        dict_bytes,
                        count=1,
                    )
                body = dict_bytes.rstrip(b"\r\n") + b"\nstream\n" + repaired + b"\nendstream"
                return body, decoded
        size *= 2
    raise ExtractionError(f"对象 {expected_obj} 太大或结构异常，无法完整解析")


def parse_indirect_stored(
    overlay: bytes,
    stored_offset: int,
    expected_obj: int,
    warnings: list[str],
) -> tuple[bytes, bytes | None]:
    chunk = overlay[stored_offset:]
    hm = re.match(rb"(\d+)\s+(\d+)\s+obj(?:\r\n|\r|\n|\s)", chunk)
    if not hm or int(hm.group(1)) != expected_obj:
        raise ExtractionError(f"孤立对象 {expected_obj} 的对象头无效")
    body_start = hm.end()
    stream_kw = chunk.find(b"stream", body_start)
    first_endobj = chunk.find(b"endobj", body_start)
    if first_endobj >= 0 and (stream_kw < 0 or first_endobj < stream_kw):
        return chunk[body_start:first_endobj].rstrip(b"\r\n"), None
    if stream_kw < 0:
        raise ExtractionError(f"孤立对象 {expected_obj} 不完整")
    dict_bytes = chunk[body_start:stream_kw]
    lm = re.search(rb"/Length\s+(\d+)\b", dict_bytes)
    if not lm:
        raise ExtractionError(f"孤立对象 {expected_obj} 缺少直接 Length")
    length = int(lm.group(1))
    ds = stream_kw + 6
    if chunk[ds:ds + 2] == b"\r\n":
        ds += 2
    elif chunk[ds:ds + 1] in (b"\r", b"\n"):
        ds += 1
    data = chunk[ds:ds + length]
    repaired, decoded = (data, None)
    if b"FlateDecode" in dict_bytes:
        try:
            repaired, decoded = repair_flate(data)
        except ExtractionError as exc:
            warnings.append(f"孤立对象 {expected_obj} 的压缩流未修复：{exc}")
    if len(repaired) != len(data):
        dict_bytes = re.sub(rb"/Length\s+\d+\b", f"/Length {len(repaired)}".encode(), dict_bytes, count=1)
    return dict_bytes.rstrip(b"\r\n") + b"\nstream\n" + repaired + b"\nendstream", decoded


def expand_object_streams(
    entries: dict[int, tuple[int, int, int]],
    bodies: dict[int, bytes],
    decoded_streams: dict[int, bytes],
) -> None:
    needed = sorted({field2 for typ, field2, _ in entries.values() if typ == 2})
    cache: dict[int, dict[int, bytes]] = {}
    for objstm_no in needed:
        body = bodies.get(objstm_no)
        decoded = decoded_streams.get(objstm_no)
        if body is None or decoded is None:
            raise ExtractionError(f"对象流 {objstm_no} 缺失或无法解压")
        sm = body.find(b"stream\n")
        if sm < 0:
            raise ExtractionError(f"对象 {objstm_no} 不是有效对象流")
        dict_bytes = body[:sm]
        nm = re.search(rb"/N\s+(\d+)", dict_bytes)
        fm = re.search(rb"/First\s+(\d+)", dict_bytes)
        if not nm or not fm:
            raise ExtractionError(f"对象流 {objstm_no} 缺少 N/First")
        n, first = int(nm.group(1)), int(fm.group(1))
        nums = [int(x) for x in re.findall(rb"\d+", decoded[:first])]
        if len(nums) < 2 * n:
            raise ExtractionError(f"对象流 {objstm_no} 的索引头不完整")
        pairs = list(zip(nums[0:2 * n:2], nums[1:2 * n:2]))
        content = decoded[first:]
        extracted: dict[int, bytes] = {}
        for i, (embedded_no, rel) in enumerate(pairs):
            end = pairs[i + 1][1] if i + 1 < len(pairs) else len(content)
            extracted[embedded_no] = content[rel:end].strip(b"\r\n \t")
        cache[objstm_no] = extracted
    for no, (typ, objstm_no, _) in entries.items():
        if typ != 2:
            continue
        item = cache.get(objstm_no, {}).get(no)
        if item is None:
            raise ExtractionError(f"压缩对象 {no} 未在对象流 {objstm_no} 中找到")
        bodies[no] = item


def recover_referenced_orphans(
    overlay: bytes,
    headers: dict[tuple[int, int], list[int]],
    bodies: dict[int, bytes],
    warnings: list[str],
    log: LogFn,
) -> None:
    """Recover directly stored objects omitted from XRef but referenced by recovered objects."""
    for _ in range(4):
        refs: set[int] = set()
        for body in bodies.values():
            refs.update(int(x) for x in re.findall(rb"(?<!\d)(\d+)\s+\d+\s+R\b", body))
        missing = sorted(refs - set(bodies))
        added = 0
        for no in missing:
            positions = headers.get((no, 0), [])
            if len(positions) != 1:
                continue
            try:
                body, decoded = parse_indirect_stored(overlay, positions[0], no, warnings)
            except ExtractionError:
                continue
            bodies[no] = body
            added += 1
        if not added:
            break
        log(f"补回 {added} 个未列入 XRef 的被引用对象")



def _make_stream(data: bytes, extra: bytes = b"", compress: bool = True) -> tuple[bytes, bytes]:
    encoded = zlib.compress(data) if compress else data
    dictionary = bytearray(b"<<")
    cleaned = extra.strip().strip(b"<>").strip()
    if cleaned:
        if not cleaned.startswith(b"/"):
            dictionary += b"/"
        dictionary += cleaned
    if compress:
        dictionary += b"/Filter/FlateDecode"
    dictionary += f"/Length {len(encoded)}>>".encode()
    return bytes(dictionary) + b"\nstream\n" + encoded + b"\nendstream", data


def _parse_tounicode_cmap(data: bytes) -> dict[int, str]:
    """Parse bfchar/bfrange blocks from a PDF ToUnicode CMap."""
    mapping: dict[int, str] = {}

    def decode_utf16(hex_bytes: bytes) -> str:
        try:
            return bytes.fromhex(hex_bytes.decode("ascii")).decode("utf-16-be", errors="ignore")
        except Exception:
            return ""

    for block in re.findall(rb"beginbfchar(.*?)endbfchar", data, re.S):
        for src, dst in re.findall(rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>", block):
            text = decode_utf16(dst)
            if text:
                mapping[int(src, 16)] = text

    for block in re.findall(rb"beginbfrange(.*?)endbfrange", data, re.S):
        # Array bfrange: <0001> <0003> [<4E00> <4E01> <4E02>]
        array_spans: list[tuple[int, int]] = []
        for match in re.finditer(
            rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*\[([^]]+)\]", block, re.S
        ):
            array_spans.append(match.span())
            a, b = int(match.group(1), 16), int(match.group(2), 16)
            vals = re.findall(rb"<([0-9A-Fa-f]+)>", match.group(3))
            for cid, val in zip(range(a, b + 1), vals):
                text = decode_utf16(val)
                if text:
                    mapping[cid] = text

        # Remove array forms before parsing sequential ranges.
        cleaned = bytearray(block)
        for a, b in array_spans:
            cleaned[a:b] = b" " * (b - a)
        for first, last, dst in re.findall(
            rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>", bytes(cleaned)
        ):
            a, b = int(first, 16), int(last, 16)
            raw = bytes.fromhex(dst.decode("ascii"))
            if len(raw) not in (2, 4) or b < a or b - a > 65535:
                continue
            start_code = int.from_bytes(raw, "big")
            width = len(raw)
            for i, cid in enumerate(range(a, b + 1)):
                try:
                    text = (start_code + i).to_bytes(width, "big").decode("utf-16-be", errors="ignore")
                except OverflowError:
                    break
                if text:
                    mapping[cid] = text
    return mapping

def _candidate_cjk_fonts() -> list[tuple[Path, int]]:
    candidates: list[tuple[Path, int]] = []
    windir = os.environ.get("WINDIR") or os.environ.get("SystemRoot")
    if windir:
        fontdir = Path(windir) / "Fonts"
        for name in ("simsun.ttc", "simsun.ttf", "msyh.ttc", "msyh.ttf", "Deng.ttf", "simkai.ttf"):
            candidates.append((fontdir / name, 0))
    # Common Linux/macOS fonts; they are used only as an embedded fallback in the output PDF.
    for name in (
        "/usr/share/fonts/truetype/arphic-gbsn00lp/gbsn00lp.ttf",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/opentype/noto/NotoSerifCJK-Regular.ttc",
        "/System/Library/Fonts/PingFang.ttc",
        "/System/Library/Fonts/Supplemental/Songti.ttc",
    ):
        candidates.append((Path(name), 0))
    return [(p, idx) for p, idx in candidates if p.exists()]


def _build_fallback_cjk_font(
    cmap_data: bytes,
    font_obj_no: int,
    cidset_obj_no: int | None,
    descriptor_no: int,
    cidfont_no: int,
    type0_no: int,
    next_obj_no: int,
    warnings: list[str],
    log: LogFn,
) -> tuple[dict[int, bytes], int]:
    """Build a Type0 font from an installed CJK font and a recovered ToUnicode CMap."""
    try:
        from fontTools import subset
        from fontTools.ttLib import TTFont
        logging.getLogger("fontTools").setLevel(logging.ERROR)
    except Exception as exc:  # pragma: no cover - depends on local installation
        raise ExtractionError("嵌入中文字体损坏，且未安装 fonttools，无法自动重建") from exc

    cmap = _parse_tounicode_cmap(cmap_data)
    codepoints: set[int] = set()
    cid_to_cp: dict[int, int] = {}
    for cid, text in cmap.items():
        if not text:
            continue
        cp = ord(text[0])
        cid_to_cp[cid] = cp
        codepoints.add(cp)
    if not codepoints:
        raise ExtractionError("无法从 ToUnicode 字符映射中恢复中文字体")

    font = None
    chosen: Path | None = None
    for path, font_number in _candidate_cjk_fonts():
        try:
            candidate = TTFont(path, fontNumber=font_number, lazy=False)
            best = candidate.getBestCmap() or {}
            coverage = sum(1 for cp in codepoints if cp in best)
            if coverage >= max(1, int(len(codepoints) * 0.85)):
                font = candidate
                chosen = path
                break
            candidate.close()
        except Exception:
            continue
    if font is None or chosen is None:
        raise ExtractionError("嵌入中文字体损坏，且本机未找到可用的宋体/中文字体")

    options = subset.Options()
    options.layout_features = []
    options.name_IDs = [1, 2, 3, 4, 6]
    options.name_legacy = True
    options.name_languages = [0x409, 0x804]
    options.notdef_glyph = True
    options.notdef_outline = True
    options.recommended_glyphs = True
    subsetter = subset.Subsetter(options=options)
    subsetter.populate(unicodes=codepoints)
    subsetter.subset(font)
    buf = io.BytesIO()
    font.save(buf)
    font_bytes = buf.getvalue()
    font.close()

    rebuilt = TTFont(io.BytesIO(font_bytes), lazy=False)
    best = rebuilt.getBestCmap() or {}
    order = rebuilt.getGlyphOrder()
    gid_by_name = {name: i for i, name in enumerate(order)}
    hmtx = rebuilt["hmtx"].metrics
    units = rebuilt["head"].unitsPerEm or 1000
    max_cid = max(cid_to_cp)
    cid_map = bytearray((max_cid + 1) * 2)
    widths: list[tuple[int, int]] = []
    for cid, cp in sorted(cid_to_cp.items()):
        glyph_name = best.get(cp, ".notdef")
        gid = gid_by_name.get(glyph_name, 0)
        cid_map[cid * 2:cid * 2 + 2] = int(gid).to_bytes(2, "big")
        advance = hmtx.get(glyph_name, (units, 0))[0]
        widths.append((cid, max(1, round(advance * 1000 / units))))
    rebuilt.close()

    width_parts = [f"{cid}[{width}]" for cid, width in widths]
    cidmap_no = next_obj_no
    objects: dict[int, bytes] = {}
    objects[font_obj_no], _ = _make_stream(font_bytes, b"Length1 " + str(len(font_bytes)).encode(), True)
    objects[cidmap_no], _ = _make_stream(bytes(cid_map), b"", True)
    cidset_clause = f"/CIDSet {cidset_obj_no} 0 R" if cidset_obj_no is not None else ""
    objects[descriptor_no] = (
        f"<</Type/FontDescriptor/FontName/FallbackCJK/Flags 4/FontBBox[-200 -300 1200 1100]"
        f"/ItalicAngle 0/Ascent 900/Descent -250/CapHeight 700/StemV 80"
        f"/FontFile2 {font_obj_no} 0 R{cidset_clause}>>"
    ).encode()
    objects[cidfont_no] = (
        f"<</Type/Font/Subtype/CIDFontType2/BaseFont/FallbackCJK"
        f"/CIDSystemInfo<</Registry(Adobe)/Ordering(Identity)/Supplement 0>>"
        f"/FontDescriptor {descriptor_no} 0 R/CIDToGIDMap {cidmap_no} 0 R/DW 1000"
        f"/W[{' '.join(width_parts)}]>>"
    ).encode()
    # ToUnicode is attached by the caller because its object number is profile-specific.
    log(f"使用本机字体 {chosen.name} 重建损坏的中文字体子集")
    warnings.append(f"原嵌入宋体损坏，已使用本机字体 {chosen.name} 重建字形")
    return objects, cidmap_no + 1



def _all_references(bodies: dict[int, bytes]) -> set[int]:
    refs: set[int] = set()
    for body in bodies.values():
        refs.update(int(x) for x in re.findall(rb"(?<!\d)(\d+)\s+\d+\s+R\b", body))
    return refs



def recover_single_page_schematic(bodies: dict[int, bytes], root_no: int, log: LogFn) -> bool:
    """Repair the compact single-page schematic variant with a missing page tree wrapper."""
    root = bodies.get(root_no, b"")
    pm = re.search(rb"/Pages\s+(\d+)\s+\d+\s+R", root)
    if not pm:
        return False
    pages_no = int(pm.group(1))
    if pages_no in bodies:
        return False
    page_candidates = [
        (no, body) for no, body in bodies.items()
        if (b"/Type/Page" in body or b"/Type /Page" in body)
        and not (b"/Type/Pages" in body or b"/Type /Pages" in body)
    ]
    if len(page_candidates) != 1:
        return False
    page_no, page = page_candidates[0]
    parent = re.search(rb"/Parent\s+(\d+)\s+\d+\s+R", page)
    if not parent or int(parent.group(1)) != pages_no:
        return False
    media = re.search(rb"/MediaBox\s*\[\s*0\s+0\s+842\s+595\s*\]", page)
    if not media:
        return False

    bodies[pages_no] = f"<</Type/Pages/Kids[{page_no} 0 R]/Count 1>>".encode()
    refs = _all_references(bodies)
    missing = sorted(refs - set(bodies))
    for no in missing:
        if any(re.search(fr"/GS\d*\s+{no}\s+\d+\s+R".encode(), body) for body in bodies.values()):
            bodies[no] = b"<</Type/ExtGState/BM/Normal/CA 1/ca 1>>"
            continue
        if re.search(fr"/Contents\s+{no}\s+\d+\s+R".encode(), page):
            body, _ = _make_stream(b"q\n/Fm0 Do\nQ\n", b"", False)
            bodies[no] = body
    log(f"已重建单页原理图的页树和绘图入口（Pages {pages_no}）")
    return True

def recover_a3_code_listing_resources(
    overlay: bytes,
    headers: dict[tuple[int, int], list[int]],
    bodies: dict[int, bytes],
    decoded_streams: dict[int, bytes],
    root_no: int,
    warnings: list[str],
    log: LogFn,
) -> bool:
    """Recover the A3 source-code/document print variant used by this wrapper family."""
    first_page_no = root_no + 1
    page = bodies.get(first_page_no, b"")
    if not page or not re.search(rb"/MediaBox\s*\[\s*0\s+0\s+842(?:\.0+)?\s+1191(?:\.0+)?\s*\]", page):
        return False

    cm = re.search(rb"/CS0\s+(\d+)\s+\d+\s+R", page)
    gm = re.search(rb"/GS0\s+(\d+)\s+\d+\s+R", page)
    font_refs = {name.decode("ascii"): int(no) for name, no in re.findall(rb"/(C2_\d+|TT\d+)\s+(\d+)\s+\d+\s+R", page)}
    if not cm or not gm or "C2_0" not in font_refs or "TT0" not in font_refs or "TT1" not in font_refs:
        return False
    color_no, gs_no = int(cm.group(1)), int(gm.group(1))
    cjk_no, courier_no, courier_bold_no = font_refs["C2_0"], font_refs["TT0"], font_refs["TT1"]

    # Public dictionaries are removed from XRef, while their streams survive between
    # the first page and the first common dictionary object.
    scan_end = min(color_no, gs_no, cjk_no, courier_no, courier_bold_no)
    for no in range(first_page_no + 1, scan_end):
        if no in bodies:
            continue
        positions = headers.get((no, 0), [])
        if len(positions) != 1:
            continue
        try:
            body, decoded = parse_indirect_stored(overlay, positions[0], no, warnings)
        except ExtractionError:
            continue
        bodies[no] = body
        if decoded is not None:
            decoded_streams[no] = decoded

    icc_candidates = [no for no, body in bodies.items() if b"/Alternate/DeviceRGB" in body and no > root_no]
    cmap_candidates = [no for no, data in decoded_streams.items() if b"begincmap" in data and no > root_no]
    font_candidates = [no for no, body in bodies.items() if b"/Length1" in body and no > root_no]
    if not icc_candidates or not cmap_candidates or not font_candidates:
        return False
    icc_no = min(icc_candidates)
    cmap_no = min(cmap_candidates)
    fontfile_no = min(font_candidates)
    cidset_no = fontfile_no - 1 if fontfile_no - 1 in bodies else None

    bodies[color_no] = f"[/ICCBased {icc_no} 0 R]".encode()
    bodies[gs_no] = b"<</Type/ExtGState/SA false/SM 0.02/OP false/op false/OPM 1>>"

    descriptor_no, cidfont_no = cjk_no - 2, cjk_no - 1
    cidset_clause = f"/CIDSet {cidset_no} 0 R" if cidset_no is not None else ""
    bodies[descriptor_no] = (
        f"<</Type/FontDescriptor/FontName/RecoveredNSimSun/Flags 7/FontBBox[-8 -145 1000 859]"
        f"/ItalicAngle 0/Ascent 859/Descent -140/CapHeight 684/StemV 80"
        f"/FontFile2 {fontfile_no} 0 R{cidset_clause}>>"
    ).encode()
    bodies[cidfont_no] = (
        f"<</Type/Font/Subtype/CIDFontType2/BaseFont/RecoveredNSimSun"
        f"/CIDSystemInfo<</Registry(Adobe)/Ordering(Identity)/Supplement 0>>"
        f"/FontDescriptor {descriptor_no} 0 R/CIDToGIDMap/Identity/DW 1000>>"
    ).encode()
    bodies[cjk_no] = (
        f"<</Type/Font/Subtype/Type0/BaseFont/RecoveredNSimSun/Encoding/Identity-H"
        f"/DescendantFonts[{cidfont_no} 0 R]/ToUnicode {cmap_no} 0 R>>"
    ).encode()
    widths_256 = "[" + " ".join(["600"] * 256) + "]"
    bodies[courier_no - 1] = (
        b"<</Type/FontDescriptor/FontName/CourierNewPSMT/Flags 34/FontBBox[-122 -680 623 1021]"
        b"/ItalicAngle 0/Ascent 832/Descent -300/CapHeight 1000/StemV 42/XHeight 1000>>"
    )
    bodies[courier_no] = (
        f"<</Type/Font/Subtype/TrueType/BaseFont/CourierNewPSMT/Encoding/WinAnsiEncoding"
        f"/FirstChar 0/LastChar 255/Widths{widths_256}/FontDescriptor {courier_no - 1} 0 R>>"
    ).encode()
    bodies[courier_bold_no - 1] = (
        b"<</Type/FontDescriptor/FontName/CourierNewPS-BoldMT/Flags 34/FontBBox[-192 -710 702 1221]"
        b"/ItalicAngle 0/Ascent 832/Descent -300/CapHeight 1000/StemV 100/XHeight 1000>>"
    )
    bodies[courier_bold_no] = (
        f"<</Type/Font/Subtype/TrueType/BaseFont/CourierNewPS-BoldMT/Encoding/WinAnsiEncoding"
        f"/FirstChar 0/LastChar 255/Widths{widths_256}/FontDescriptor {courier_bold_no - 1} 0 R>>"
    ).encode()

    top_pages = _find_top_pages(bodies)
    if top_pages is None:
        return False
    if root_no not in bodies:
        extra = []
        for key, label in ((b"/Outlines", "Outlines"), (b"/AcroForm", "AcroForm")):
            # Prefer the known neighboring objects when they exist; these are optional.
            pass
        catalog = f"<</Type/Catalog/Pages {top_pages} 0 R"
        if root_no - 103 in bodies and b"/Type/Outlines" in bodies.get(root_no - 103, b""):
            catalog += f"/Outlines {root_no - 103} 0 R"
        if root_no + 18 in bodies and b"/Fields" in bodies.get(root_no + 18, b""):
            catalog += f"/AcroForm {root_no + 18} 0 R"
        catalog += ">>"
        bodies[root_no] = catalog.encode()

    # Watermark-related objects in one A3 variant are also removed.
    refs = _all_references(bodies)
    missing = refs - set(bodies)
    ocg_objects = [no for no, body in bodies.items() if b"/Type/OCG" in body or b"/Type /OCG" in body]
    for missing_no in sorted(missing):
        # /OC <n> references an optional-content membership dictionary.
        if any(re.search(fr"/OC\s+{missing_no}\s+\d+\s+R".encode(), b) for b in bodies.values()) and ocg_objects:
            bodies[missing_no] = f"<</Type/OCMD/OCGs {ocg_objects[0]} 0 R>>".encode()
            continue
        # A watermark Type0 font may point to an already-recovered DescendantFonts array.
        if missing_no - 1 in bodies and bodies[missing_no - 1].lstrip().startswith(b"["):
            bodies[missing_no] = (
                f"<</Type/Font/Subtype/Type0/BaseFont/SimSun/Encoding/UniGB-UTF16-H"
                f"/DescendantFonts {missing_no - 1} 0 R>>"
            ).encode()

    log(f"已重建 A3 代码文档的公共色彩、字体和目录资源（Root {root_no}）")
    return True

def _find_standard_cover_parent(bodies: dict[int, bytes], cover_no: int) -> int | None:
    needle = fr"(?<!\d){cover_no}\s+0\s+R".encode()
    for no, body in bodies.items():
        if (b"/Type/Pages" in body or b"/Type /Pages" in body) and re.search(needle, body):
            return no
    return None


def _find_top_pages(bodies: dict[int, bytes]) -> int | None:
    for no, body in bodies.items():
        if not (b"/Type/Pages" in body or b"/Type /Pages" in body):
            continue
        if not re.search(rb"/Parent\s+\d+\s+\d+\s+R", body):
            return no
    return None


def _resource_targets(bodies: dict[int, bytes]) -> tuple[int | None, int | None, dict[str, int]]:
    color: int | None = None
    gs: int | None = None
    fonts: dict[str, int] = {}
    for body in bodies.values():
        if b"/Resources" not in body and b"/ColorSpace" not in body and b"/Font" not in body:
            continue
        if color is None:
            m = re.search(rb"/Cs6\s+(\d+)\s+\d+\s+R", body)
            if m:
                color = int(m.group(1))
        if gs is None:
            m = re.search(rb"/GS1\s+(\d+)\s+\d+\s+R", body)
            if m:
                gs = int(m.group(1))
        for name, no in re.findall(rb"/(TT\d+)\s+(\d+)\s+\d+\s+R", body):
            fonts[name.decode("ascii")] = int(no)
    return color, gs, fonts


def _parse_image_dims(body: bytes) -> tuple[int | None, int | None, bool]:
    wm = re.search(rb"/Width\s+(\d+)", body)
    hm = re.search(rb"/Height\s+(\d+)", body)
    return (int(wm.group(1)) if wm else None, int(hm.group(1)) if hm else None, b"CCITTFaxDecode" in body)


def recover_standard_removed_resources(
    overlay: bytes,
    headers: dict[tuple[int, int], list[int]],
    bodies: dict[int, bytes],
    decoded_streams: dict[int, bytes],
    root_no: int,
    warnings: list[str],
    log: LogFn,
) -> None:
    """Recover the standard Word/Distiller cover and public resources removed by this EXE wrapper family."""
    cover_no = root_no + 1
    resource_no = cover_no + 1
    parent_no = _find_standard_cover_parent(bodies, cover_no)
    top_pages_no = _find_top_pages(bodies)
    color_no, gs_no, font_targets = _resource_targets(bodies)
    required_fonts = {"TT1", "TT2", "TT4", "TT7"}
    if parent_no is None or top_pages_no is None or color_no is None or gs_no is None or not required_fonts.issubset(font_targets):
        raise ExtractionError("缺失的 Root 对象不符合已支持的 PDF 封装模板")

    # Cover resources are physically present but intentionally omitted from XRef.
    upper = min([n for n in (color_no, gs_no, *font_targets.values()) if n > cover_no])
    for no in range(cover_no + 2, upper):
        if no in bodies:
            continue
        positions = headers.get((no, 0), [])
        if len(positions) != 1:
            continue
        try:
            body, decoded = parse_indirect_stored(overlay, positions[0], no, warnings)
        except ExtractionError:
            continue
        bodies[no] = body
        if decoded is not None:
            decoded_streams[no] = decoded

    # One overlapping, non-visible cover content stream is normally corrupted by rotation.
    bad_blank = cover_no + 3
    if bad_blank not in decoded_streams:
        bodies[bad_blank], decoded_streams[bad_blank] = _make_stream(b"", b"", True)
        warnings.append(f"封面辅助流对象 {bad_blank} 已替换为空流")

    to_unicode_1, to_unicode_2, to_unicode_7 = cover_no + 8, cover_no + 9, cover_no + 10
    icc_no = cover_no + 14
    k_cidset, k_font = cover_no + 15, cover_no + 16
    d_cidset, d_font = cover_no + 17, cover_no + 18

    # Two variants exist: Times fonts may be embedded before the final SimSun pair.
    candidate_19 = bodies.get(cover_no + 19, b"")
    candidate_20 = bodies.get(cover_no + 20, b"")
    has_embedded_times = b"/Length1" in candidate_19 and b"/Length1" in candidate_20
    if has_embedded_times:
        s_cidset, s_font = cover_no + 21, cover_no + 22
        image_start = cover_no + 23
    else:
        s_cidset, s_font = cover_no + 19, cover_no + 20
        image_start = cover_no + 21

    # Ensure essential orphan streams were actually recovered.
    for no in (to_unicode_1, to_unicode_2, to_unicode_7, icc_no, k_cidset, k_font, d_cidset, d_font, s_cidset, s_font):
        if no not in bodies:
            raise ExtractionError(f"封面公共资源对象 {no} 缺失")

    # Color and graphics state used by both body pages and cover.
    bodies[color_no] = f"[/ICCBased {icc_no} 0 R]".encode()
    bodies[gs_no] = b"<</Type/ExtGState/SA true/SM 0.02/OP false/op false/OPM 1>>"

    def make_cjk(target: int, base_name: str, cidset: int, font_stream: int, tounicode: int) -> None:
        cidfont = target - 2
        descriptor = target - 1
        bodies[cidfont] = (
            f"<</Type/Font/Subtype/CIDFontType2/BaseFont/{base_name}"
            f"/CIDSystemInfo<</Registry(Adobe)/Ordering(Identity)/Supplement 0>>"
            f"/FontDescriptor {descriptor} 0 R/CIDToGIDMap/Identity/DW 1000>>"
        ).encode()
        bodies[descriptor] = (
            f"<</Type/FontDescriptor/FontName/{base_name}/Flags 4/FontBBox[-200 -350 1200 1100]"
            f"/ItalicAngle 0/Ascent 950/Descent -300/CapHeight 750/StemV 80"
            f"/FontFile2 {font_stream} 0 R/CIDSet {cidset} 0 R>>"
        ).encode()
        bodies[target] = (
            f"<</Type/Font/Subtype/Type0/BaseFont/{base_name}/Encoding/Identity-H"
            f"/DescendantFonts[{cidfont} 0 R]/ToUnicode {tounicode} 0 R>>"
        ).encode()

    make_cjk(font_targets["TT1"], "RecoveredSTKaiti", k_cidset, k_font, to_unicode_1)
    make_cjk(font_targets["TT2"], "RecoveredDengXian", d_cidset, d_font, to_unicode_2)

    # Times is standard WinAnsi on this cover; using base fonts is more robust than damaged subset streams.
    bodies[font_targets["TT4"]] = b"<</Type/Font/Subtype/Type1/BaseFont/Times-Roman/Encoding/WinAnsiEncoding>>"
    if "TT6" in font_targets:
        bodies[font_targets["TT6"]] = b"<</Type/Font/Subtype/Type1/BaseFont/Times-Bold/Encoding/WinAnsiEncoding>>"

    reserved_max = max(
        max(bodies, default=0),
        max(headers, default=(0, 0))[0],
        root_no,
        cover_no,
        resource_no,
        color_no,
        gs_no,
        *font_targets.values(),
    )
    next_obj = reserved_max + 1
    if s_font in decoded_streams:
        make_cjk(font_targets["TT7"], "RecoveredSimSun", s_cidset, s_font, to_unicode_7)
    else:
        cmap_data = decoded_streams.get(to_unicode_7)
        if cmap_data is None:
            raise ExtractionError("宋体损坏且 ToUnicode 映射无法解压")
        extra, next_obj = _build_fallback_cjk_font(
            cmap_data,
            s_font,
            s_cidset,
            font_targets["TT7"] - 1,
            font_targets["TT7"] - 2,
            font_targets["TT7"],
            next_obj,
            warnings,
            log,
        )
        bodies.update(extra)
        bodies[font_targets["TT7"]] = (
            f"<</Type/Font/Subtype/Type0/BaseFont/FallbackCJK/Encoding/Identity-H"
            f"/DescendantFonts[{font_targets['TT7'] - 2} 0 R]/ToUnicode {to_unicode_7} 0 R>>"
        ).encode()

    # Locate the fixed Word cover image masks by dimensions, independent of object numbers.
    images: dict[tuple[int | None, int | None, bool], int] = {}
    for no in range(image_start, upper):
        body = bodies.get(no, b"")
        if b"/Subtype/Image" in body or b"/Subtype /Image" in body:
            images[_parse_image_dims(body)] = no
    checker_no = cover_no + 12
    xmap: dict[str, int] = {}
    dimension_names = {
        "Im2": (967, 275, True),
        "Im5": (343, 359, False),
        "Im6": (343, 343, False),
        "Im7": (359, 343, False),
        "Im11": (279, 327, False),
        "Im12": (215, 215, False),
        "Im13": (263, 263, False),
    }
    for name, key in dimension_names.items():
        if key in images:
            xmap[name] = images[key]
    xmap["Im4"] = checker_no
    empty_form_no = next_obj
    bodies[empty_form_no] = (
        b"<</Type/XObject/Subtype/Form/FormType 1/BBox[0 0 1003 544]/Resources<<>>/Length 0>>\n"
        b"stream\n\nendstream"
    )
    xmap["Im1"] = empty_form_no

    font_entries = [f"/{name} {font_targets[name]} 0 R" for name in ("TT1", "TT2", "TT4", "TT6", "TT7") if name in font_targets]
    x_entries = [f"/{name} {no} 0 R" for name, no in sorted(xmap.items(), key=lambda kv: int(kv[0][2:]))]
    bodies[resource_no] = (
        f"<</ColorSpace<</Cs6 {color_no} 0 R>>/ExtGState<</GS1 {gs_no} 0 R>>"
        f"/Font<<{' '.join(font_entries)}>>/ProcSet[/PDF/Text/ImageB/ImageC/ImageI]"
        f"/XObject<<{' '.join(x_entries)}>>>>"
    ).encode()

    contents = [cover_no + i for i in (2, 3, 4, 5, 6, 7, 11, 13)]
    bodies[cover_no] = (
        f"<</Type/Page/Parent {parent_no} 0 R/MediaBox[0 0 595.22 842]/CropBox[0 0 595.22 842]"
        f"/Rotate 0/Resources {resource_no} 0 R/Contents[{' '.join(f'{n} 0 R' for n in contents)}]>>"
    ).encode()
    bodies[root_no] = f"<</Type/Catalog/Pages {top_pages_no} 0 R/PageMode/UseNone>>".encode()
    log(f"已重建被封装器移除的目录、封面和公共资源（Root {root_no}）")

def _extract_ref(dictionary: bytes, key: bytes) -> int | None:
    m = re.search(rb"/" + re.escape(key) + rb"\s+(\d+)\s+\d+\s+R\b", dictionary)
    return int(m.group(1)) if m else None


def _page_hint(bodies: dict[int, bytes], root_no: int | None) -> int | None:
    if root_no is None:
        return None
    root = bodies.get(root_no, b"")
    pm = re.search(rb"/Pages\s+(\d+)\s+\d+\s+R", root)
    if not pm:
        return None
    pages = bodies.get(int(pm.group(1)), b"")
    cm = re.search(rb"/Count\s+(\d+)", pages)
    return int(cm.group(1)) if cm else None


def write_rebuilt_pdf(
    out_path: Path,
    bodies: dict[int, bytes],
    root_no: int,
    info_no: int | None,
) -> None:
    max_obj = max(max(bodies, default=0), root_no, info_no or 0)
    output = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}
    for no in range(1, max_obj + 1):
        body = bodies.get(no)
        if body is None:
            continue
        offsets[no] = len(output)
        output += f"{no} 0 obj\n".encode()
        output += body
        if not body.endswith((b"\n", b"\r")):
            output += b"\n"
        output += b"endobj\n"
    xref_pos = len(output)
    output += f"xref\n0 {max_obj + 1}\n".encode()
    output += b"0000000000 65535 f \n"
    for no in range(1, max_obj + 1):
        if no in offsets:
            output += f"{offsets[no]:010d} 00000 n \n".encode()
        else:
            output += b"0000000000 00000 f \n"
    trailer = f"trailer\n<< /Size {max_obj + 1} /Root {root_no} 0 R".encode()
    if info_no is not None and info_no in bodies:
        trailer += f" /Info {info_no} 0 R".encode()
    trailer += f" >>\nstartxref\n{xref_pos}\n%%EOF\n".encode()
    output += trailer
    out_path.write_bytes(output)


def extract_pdf_from_exe(
    input_path: str | Path,
    output_path: str | Path | None = None,
    log: LogFn | None = None,
) -> ExtractionResult:
    log = log or _noop
    src = Path(input_path)
    if output_path is None:
        output_path = src.with_name(src.stem + "_提取修复.pdf")
    out = Path(output_path)
    warnings: list[str] = []

    data = src.read_bytes()
    overlay_start = find_pe_overlay(data)
    raw_overlay = data[overlay_start:]
    log(f"PE 附加区起点：{overlay_start}，大小：{len(raw_overlay)} 字节")

    # This wrapper family places an 8-byte descriptor before the transformed PDF.
    overlay = raw_overlay[8:] if len(raw_overlay) >= 8 and raw_overlay[:8] in (
        b"\x00\x00\x00\x00\x01\x00\x00\x00",
        b"\x00\x00\x00\x00\x00\x00\x00\x00",
    ) else raw_overlay
    headers = scan_object_headers(overlay)
    log(f"扫描到 {sum(len(v) for v in headers.values())} 个对象头候选")

    revisions = find_xref_streams(overlay, headers)
    revisions.extend(find_classic_xrefs(overlay))
    revisions = _pick_revisions(revisions, log)

    merged: dict[int, tuple[int, int, int]] = {}
    latest_dict = b""
    xref_objnos: set[int] = set()
    for rev in revisions:
        merged.update(rev.entries)
        latest_dict = rev.dictionary
        if rev.objno is not None:
            xref_objnos.add(rev.objno)
    log(f"合并后 XRef 条目：{len(merged)}")

    deltas, chosen = infer_mapping(overlay, merged, headers, log)
    reader = LogicalReader(overlay, deltas)

    bodies: dict[int, bytes] = {}
    decoded_streams: dict[int, bytes] = {}
    failures: list[str] = []
    type1_total = sum(1 for v in merged.values() if v[0] == 1)
    done = 0
    for no, (typ, logical, _gen) in sorted(merged.items()):
        if typ != 1:
            continue
        done += 1
        try:
            body, decoded = parse_indirect_logical(reader, logical, no, warnings)
        except ExtractionError as first_exc:
            # If this object has an unambiguous stored occurrence, parse it directly.
            positions = headers.get((no, 0), [])
            fallback = chosen.get(no)
            if fallback is None and len(positions) == 1:
                fallback = positions[0]
            if fallback is None:
                failures.append(f"对象 {no}: {first_exc}")
                continue
            try:
                body, decoded = parse_indirect_stored(overlay, fallback, no, warnings)
            except ExtractionError as second_exc:
                failures.append(f"对象 {no}: {second_exc}")
                continue
        bodies[no] = body
        if decoded is not None:
            decoded_streams[no] = decoded
        if done % 100 == 0 or done == type1_total:
            log(f"已读取直接对象 {done}/{type1_total}")

    if failures:
        warnings.extend(failures[:20])
        if len(failures) > 20:
            warnings.append(f"另有 {len(failures) - 20} 个对象读取失败")

    expand_object_streams(merged, bodies, decoded_streams)
    log("已展开压缩对象流")
    recover_referenced_orphans(overlay, headers, bodies, warnings, log)

    root_no = _extract_ref(latest_dict, b"Root")
    info_no = _extract_ref(latest_dict, b"Info")
    if root_no is None:
        # Some incremental files have Root only in an earlier revision.
        for rev in reversed(revisions):
            root_no = _extract_ref(rev.dictionary, b"Root")
            if root_no is not None:
                break
    if info_no is None:
        for rev in reversed(revisions):
            info_no = _extract_ref(rev.dictionary, b"Info")
            if info_no is not None:
                break
    if root_no is None:
        raise ExtractionError("无法从 PDF 交叉引用信息确定 Root/Catalog 对象编号")
    recover_single_page_schematic(bodies, root_no, log)

    # A3 code-listing variants may keep the first page while removing only the common dictionaries.
    a3_recovered = recover_a3_code_listing_resources(
        overlay, headers, bodies, decoded_streams, root_no, warnings, log
    )
    if root_no not in bodies and not a3_recovered:
        recover_standard_removed_resources(
            overlay, headers, bodies, decoded_streams, root_no, warnings, log
        )
    recover_referenced_orphans(overlay, headers, bodies, warnings, log)

    # Do not retain transport-only XRef objects in the rebuilt document.
    for no in xref_objnos:
        bodies.pop(no, None)

    if root_no not in bodies:
        raise ExtractionError("无法恢复 PDF 的 Root/Catalog 对象")

    out.parent.mkdir(parents=True, exist_ok=True)
    write_rebuilt_pdf(out, bodies, root_no, info_no)
    hint = _page_hint(bodies, root_no)
    log(f"输出完成：{out}，对象 {len(bodies)}，页数提示 {hint}")
    return ExtractionResult(src, out, len(bodies), hint, len(revisions), deltas, warnings)


__all__ = [
    "ExtractionError",
    "ExtractionResult",
    "extract_pdf_from_exe",
    "find_pe_overlay",
]
