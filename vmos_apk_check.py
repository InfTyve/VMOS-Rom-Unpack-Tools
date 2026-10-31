#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vmos_apk_check.py — 检查「内置 ROM 的 APK」能不能装、catalog 自不自洽

改完 assets/roms/*.7z 之后，最容易出问题的是两件事，且互不相干：

  1. 签名：APK 是 v2 whole-file 签名，改任何字节都会失效。
     不重签 → 安装到 90%（复制完才验签）才报错，表现得像"装到一半失败"。
  2. catalog：里面的 sha256 / sizeBytes 是运行时自检用的，
     与安装无关，但改漏了会在创建虚拟机时报
     "system image catalog entry changed or not authorized"。

本工具把这两件事分开检查，各自给结论。

用法:
    python3 vmos_apk_check.py 你的包.apk
    python3 vmos_apk_check.py 你的包.apk --json
"""

import argparse
import hashlib
import json
import os
import struct
import sys
import zipfile

VERSION = '2026.10.31.1'
BUILD_NOTE = '分离检查 APK 签名方案与 assets/roms/catalog.json 自洽性'

OK = '\u2714'
BAD = '\u2718'
WARN = '\u26a0'
INFO = '\u00b7'

SIG_IDS = {
    0x7109871a: ('v2', 'APK Signature Scheme v2'),
    0xf05368c0: ('v3', 'APK Signature Scheme v3'),
    0x1b93ad61: ('v3.1', 'APK Signature Scheme v3.1'),
    0x42726577: ('padding', '对齐填充'),
    0x6dff800d: ('stamp', 'Source Stamp v2'),
    0x504b4453: ('vendor', '厂商扩展块（非标准）'),
}

# targetSdk 达到这个值，Android 11+ 强制要求 v2 签名
MIN_SDK_FORCE_V2 = 30


def human(n):
    for u in ('B', 'KB', 'MB', 'GB'):
        if abs(n) < 1024 or u == 'GB':
            return f'{n:,.0f} {u}' if u == 'B' else f'{n:,.2f} {u}'
        n /= 1024.0


# ────────────────────────── 签名块解析 ──────────────────────────
def parse_sig_block(path):
    """返回 (块列表, 错误说明)。块列表元素为 (id, 描述, 值长度)。"""
    size = os.path.getsize(path)
    with open(path, 'rb') as f:
        f.seek(max(0, size - 65557))
        tail = f.read()
        rel = tail.rfind(b'PK\x05\x06')
        if rel < 0:
            return None, '文件末尾找不到 EOCD，不是合法 zip/APK'
        eocd_off = size - len(tail) + rel
        f.seek(eocd_off)
        eocd = f.read(22)
        cd_off = struct.unpack_from('<I', eocd, 16)[0]
        if cd_off == 0xFFFFFFFF:
            return None, 'EOCD 里 central directory 偏移是 0xFFFFFFFF（zip64），本工具未处理'

        f.seek(cd_off - 24)
        foot = f.read(24)
        if len(foot) < 24:
            return None, 'central directory 前不足 24 字节'
        bsize = struct.unpack('<Q', foot[:8])[0]
        magic = foot[8:24]
        if magic != b'APK Sig Block 42':
            return None, '没有 APK Signing Block（只有 v1 签名，或完全未签名）'
        if bsize <= 0 or cd_off - bsize - 8 < 0:
            return None, f'签名块长度异常：{bsize}'

        base = cd_off - bsize - 8
        f.seek(base)
        hsz = struct.unpack('<Q', f.read(8))[0]
        if hsz != bsize:
            return None, f'签名块头尾长度不一致：头 {hsz} / 尾 {bsize}'

        blocks = []
        end = cd_off - 24
        while f.tell() < end:
            ln = struct.unpack('<Q', f.read(8))[0]
            idd = struct.unpack('<I', f.read(4))[0]
            tag, desc = SIG_IDS.get(idd, ('unknown', f'未知块 {idd:#x}'))
            blocks.append((tag, desc, ln - 4))
            f.seek(ln - 4, 1)
        return blocks, None


def check_v1(zf):
    names = zf.namelist()
    out = []
    for n in names:
        if not n.startswith('META-INF/'):
            continue
        base = n[len('META-INF/'):]
        if '/' in base:
            continue
        ext = base.rsplit('.', 1)[-1].upper() if '.' in base else ''
        if ext in ('SF', 'RSA', 'DSA', 'EC'):
            out.append(n)
    return out


def _string_pool(data, off):
    """解析 RES_STRING_POOL chunk，返回 (字符串列表, chunk 总长)。"""
    _typ, hsz, sz = struct.unpack_from('<HHI', data, off)
    count, _style, flags = struct.unpack_from('<III', data, off + 8)
    strings_start = struct.unpack_from('<I', data, off + 20)[0]
    utf8 = bool(flags & 0x100)
    offs = struct.unpack_from('<%dI' % count, data, off + hsz)
    base = off + strings_start
    out = []
    for o in offs:
        p = base + o
        try:
            if utf8:
                n = data[p]
                p += 1
                if n & 0x80:
                    n = ((n & 0x7F) << 8) | data[p]
                    p += 1
                out.append(data[p:p + n].decode('utf-8', 'replace'))
            else:
                n = struct.unpack_from('<H', data, p)[0]
                p += 2
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | struct.unpack_from('<H', data, p)[0]
                    p += 2
                out.append(data[p:p + n * 2].decode('utf-16-le', 'replace'))
        except Exception:
            out.append('')
    return out, sz


def axml_elements(data):
    """极简 AXML 解析，返回 [(元素名, {属性名: 值})]，只保留 START_TAG。"""
    if len(data) < 8:
        return []
    if struct.unpack_from('<HHI', data, 0)[0] != 0x0003:
        return []
    strings, _ = _string_pool(data, 8)
    out = []
    off = 8
    end = len(data)
    while off + 8 <= end:
        typ, hsz, sz = struct.unpack_from('<HHI', data, off)
        if sz <= 0:
            break
        if typ == 0x0102:  # START_TAG
            # ResXMLTree_node(16B: header 8 + lineNumber 4 + comment 4)
            # 之后是 ResXMLTree_attrExt
            ns_i, name_i = struct.unpack_from('<II', data, off + 16)
            attr_start, attr_size, attr_count = struct.unpack_from('<HHH', data, off + 24)
            attrs = {}
            p = off + 16 + attr_start
            for _ in range(attr_count):
                try:
                    _ns, an, _raw = struct.unpack_from('<III', data, p)
                    dtype = data[p + 15]          # typedValue.dataType
                    dval = struct.unpack_from('<I', data, p + 16)[0]
                except Exception:
                    break
                key = strings[an] if an < len(strings) else f'@{an}'
                if dtype == 0x10:      # TYPE_INT_DEC
                    val = dval
                elif dtype == 0x03:    # TYPE_STRING
                    val = strings[dval] if dval < len(strings) else ''
                elif dtype == 0x12:    # TYPE_BOOLEAN
                    val = bool(dval)
                else:
                    val = dval
                attrs[key] = val
                p += attr_size or 20
            name = strings[name_i] if name_i < len(strings) else ''
            out.append((name, attrs))
        off += sz
    return out


def read_manifest_sdk(zf):
    """从二进制 AndroidManifest 读 (package, minSdk, targetSdk)。读不到返回 None。"""
    try:
        data = zf.read('AndroidManifest.xml')
    except KeyError:
        return None, None, None
    pkg = mine = target = None
    for name, attrs in axml_elements(data):
        if name == 'manifest':
            pkg = attrs.get('package') or pkg
        elif name == 'uses-sdk':
            mine = attrs.get('minSdkVersion', mine)
            target = attrs.get('targetSdkVersion', target)
    return pkg, mine, target


# ────────────────────────── catalog 校验 ──────────────────────────
def stream_sha256(zf, name, chunk=1 << 22):
    h = hashlib.sha256()
    n = 0
    with zf.open(name) as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            n += len(b)
            h.update(b)
    return h.hexdigest(), n


def check_catalog(zf, deep=True):
    """返回 (条目列表, 错误)。条目 = dict，含 catalog 声明值与实际值。"""
    try:
        raw = zf.read('assets/roms/catalog.json')
    except KeyError:
        return None, 'assets/roms/catalog.json 不存在（可能是纯在线模式，不是 embedded）'

    try:
        cat = json.loads(raw.decode('utf-8'))
    except Exception as e:
        return None, f'catalog.json 不是合法 JSON：{e}'

    roms = cat.get('roms') or []
    if not roms:
        return [], None

    out = []
    for r in roms:
        item = {
            'id': r.get('id'),
            'assetPath': r.get('assetPath'),
            'declared_size': r.get('sizeBytes'),
            'declared_sha': (r.get('sha256') or '').lower(),
            'declared_version': r.get('romVersion'),
            'declared_android': r.get('androidVersion'),
            'exists': False,
            'actual_size': None,
            'actual_sha': None,
        }
        ap = r.get('assetPath')
        # catalog 里的路径是相对 assets/ 的
        real = None
        for cand in (f'assets/{ap}', ap) if ap else ():
            if cand in zf.namelist():
                real = cand
                break
        item['real_path'] = real
        if real:
            item['exists'] = True
            if deep:
                sha, n = stream_sha256(zf, real)
                item['actual_sha'] = sha
                item['actual_size'] = n
            else:
                item['actual_size'] = zf.getinfo(real).file_size
        out.append(item)
    return out, None


# ────────────────────────── 报告 ──────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description='检查内置 ROM 的 APK：签名方案 + catalog 自洽性',
        epilog='例：python3 vmos_apk_check.py vmos-plus-mod.apk')
    ap.add_argument('apk', help='要检查的 APK')
    ap.add_argument('--json', action='store_true', help='机器可读输出')
    ap.add_argument('--no-deep', action='store_true',
                    help='跳过实际 sha256 计算（只看文件大小，几秒完成）')
    ap.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    args = ap.parse_args()

    if not os.path.isfile(args.apk):
        sys.exit(f'文件不存在：{args.apk}')

    report = {'apk': args.apk, 'size': os.path.getsize(args.apk),
              'signature': {}, 'catalog': {}, 'problems': [], 'warnings': []}

    print(f'检查 {args.apk}  ({human(report["size"])})')
    print()

    # ── 1. 签名 ──
    print('【1】签名方案')
    blocks, err = parse_sig_block(args.apk)
    with zipfile.ZipFile(args.apk) as zf:
        v1 = check_v1(zf)
        pkg, minsdk, target = read_manifest_sdk(zf)

    if err:
        print(f'  {BAD} {err}')
        report['signature']['error'] = err
    else:
        tags = [b[0] for b in blocks]
        for tag, desc, ln in blocks:
            print(f'  {INFO} {desc}（{ln:,} 字节）')
        report['signature']['blocks'] = tags

    has_v2 = bool(not err and any(b[0] in ('v2', 'v3', 'v3.1') for b in blocks))
    report['signature']['has_v2_family'] = has_v2
    report['signature']['v1'] = bool(v1)

    # v1 只在没有 v2 时才要紧；有 v2 时缺 v1 完全正常
    if v1:
        print(f'  {INFO} v1 签名：有（{len(v1)} 个文件）')
    else:
        mark = INFO if has_v2 else BAD
        print(f'  {mark} v1 签名：没有' + ('（有 v2，正常）' if has_v2 else '（且没有 v2）'))
    if pkg:
        sdks = []
        if minsdk is not None:
            sdks.append(f'minSdk {minsdk}')
        if target is not None:
            sdks.append(f'targetSdk {target}')
        print(f'  {INFO} 包名 {pkg}' + ('，' + ' / '.join(sdks) if sdks else ''))
        report['package'] = pkg
        report['target_sdk'] = target

    if not has_v2 and not err:
        print(f'  {BAD} 只有 v1，没有 v2/v3')
    if not has_v2:
        if target and target >= MIN_SDK_FORCE_V2:
            report['problems'].append(
                f'targetSdk {target} ≥ {MIN_SDK_FORCE_V2}，Android 11+ 强制要求 v2 签名，'
                '当前没有 v2/v3 → 一定装不上')
        else:
            report['problems'].append(
                '没有 v2/v3 签名。targetSdk 未知，但现代 Android（11+）对多数应用强制 v2，'
                '大概率装不上')

    # ── 2. catalog ──
    print()
    print('【2】catalog.json 与实际 ROM')
    with zipfile.ZipFile(args.apk) as zf:
        items, cerr = check_catalog(zf, deep=not args.no_deep)

    if cerr:
        print(f'  {WARN} {cerr}')
        report['catalog']['error'] = cerr
    else:
        for it in items:
            print(f'  {INFO} {it["id"]}  (Android {it["declared_android"]}, '
                  f'romVersion {it["declared_version"]})')
            ap_ = it['assetPath']
            if not it['exists']:
                print(f'    {BAD} 包内没有 {ap_}')
                report['problems'].append(f'{it["id"]} 声明的 {ap_} 在包里不存在')
                continue
            if it['actual_size'] is not None:
                same_size = it['actual_size'] == it['declared_size']
                msg = (f'    {"✔" if same_size else "✘"} size  '
                       f'声明 {it["declared_size"]:,} / 实际 {it["actual_size"]:,}')
                print(msg.replace('✔', OK).replace('✘', BAD))
                if not same_size:
                    report['problems'].append(
                        f'{it["id"]} sizeBytes 不符：声明 {it["declared_size"]}，'
                        f'实际 {it["actual_size"]}')
            if it['actual_sha']:
                same_sha = it['actual_sha'] == it['declared_sha']
                print(f'    {OK if same_sha else BAD} sha256 声明 {it["declared_sha"][:16]}… / '
                      f'实际 {it["actual_sha"][:16]}…')
                if not same_sha:
                    report['problems'].append(
                        f'{it["id"]} sha256 不符：需要把 catalog 改成 '
                        f'{it["actual_sha"]}')

    # ── 3. 结论 ──
    print()
    print('【3】结论')
    if not report['problems']:
        print(f'  {OK} 签名与 catalog 都没问题')
    else:
        for i, p in enumerate(report['problems'], 1):
            print(f'  {BAD} [{i}] {p}')

    print()
    print('提醒：catalog 只影响运行时（创建虚拟机时的自检），'
          '不影响安装。')
    print('      安装失败只看签名——改完 assets 必须重新 v2 签名，且签名变了要先卸载旧版。')

    if args.json:
        print()
        print(json.dumps(report, ensure_ascii=False, indent=2))

    return 0 if not report['problems'] else 1


if __name__ == '__main__':
    sys.exit(main())
