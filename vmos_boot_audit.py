#!/usr/bin/env python3
"""VMOS 启动前体检：核对你改过的包里，VMOS 自己登记过的文件还在不在。

依据是包内三份清单（都是 VMOS 自己写的，不是我猜的）：
  boot-sidecars.json   6 个 .so，启动时会被 flat overlay 注入到 APEX 挂载点，
                       失败直接 [APEX-APP] flat overlay failed ... abort boot
  build-receipt.json   14 个构建产物（services.jar / SystemUI / init …）
  guestOSInfo          内核哈希与 ROM 版本
另外检查 SOMV 索引目录里有没有旁挂文件（.vmos_exec_overlay）被漏掉。

用法：
  python3 vmos_boot_audit.py 改过的包.7z
  python3 vmos_boot_audit.py vmos_out/          # 解包目录（包根，含 root/）
"""
import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile

import vmos_auto as va

VERSION = '2026.10.31.1'
OK, BAD, WARN = '✔', '✘', '⚠'


def human(n):
    if n is None:
        return '-'
    for u in ('B', 'KB', 'MB', 'GB'):
        if n < 1024 or u == 'GB':
            return f'{n:.1f} {u}' if u != 'B' else f'{n} B'
        n /= 1024


def sha256_of(p, limit=None):
    h = hashlib.sha256()
    left = limit
    with open(p, 'rb') as f:
        while True:
            n = 1 << 20 if left is None else min(1 << 20, left)
            if n <= 0:
                break
            b = f.read(n)
            if not b:
                break
            h.update(b)
            if left is not None:
                left -= len(b)
    return h.hexdigest()


def find_meta(root):
    """找 boot-sidecars.json / build-receipt.json / guestOSInfo"""
    want = ('boot-sidecars.json', 'build-receipt.json', 'guestOSInfo')
    found = {}
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if not d.startswith('__MACOSX')]
        for w in want:
            if w in fns and w not in found:
                found[w] = os.path.join(dp, w)
        if len(found) == len(want):
            break
    return found


def build_name_index(root):
    """basename -> [路径]，用于按文件名定位构建产物"""
    idx = {}
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if not d.startswith('__MACOSX')]
        for fn in fns:
            idx.setdefault(fn, []).append(os.path.join(dp, fn))
    return idx


def resolve(root, rel, idx):
    """先按包内相对路径找，找不到再按 basename 找（可能多处）"""
    p = os.path.join(root, rel)
    if os.path.isfile(p):
        return [p]
    base = os.path.basename(rel)
    return idx.get(base, [])


def check_one(p, size, sha, label, log):
    try:
        real = os.path.getsize(p)
    except OSError as e:
        log(f'  {BAD} {label:<52} 读不出：{e}')
        return 'bad'
    if size is not None and real != size:
        log(f'  {BAD} {label:<52} 大小 {human(real)} ≠ 登记 {human(size)}')
        return 'bad'
    if sha:
        got = sha256_of(p)
        if got != sha:
            log(f'  {BAD} {label:<52} sha256 不符\n'
                f'      登记 {sha}\n      实际 {got}')
            return 'bad'
    log(f'  {OK} {label:<52} {human(real)}')
    return 'ok'


def audit(root, log):
    meta = find_meta(root)
    log('\n[1] 包内清单')
    for k in ('guestOSInfo', 'build-receipt.json', 'boot-sidecars.json'):
        if k in meta:
            log(f'  {OK} {k}')
        else:
            log(f'  {WARN} 缺少 {k}（这个包可能不是完整整包，校验会不完整）')

    if not meta:
        return 1

    idx = build_name_index(root)
    bad = 0

    # ── sidecar：启动时 flat overlay 的源头 ──
    if 'boot-sidecars.json' in meta:
        try:
            d = json.load(open(meta['boot-sidecars.json'], encoding='utf-8'))
            files = d.get('files', [])
        except Exception as e:
            log(f'\n[2] boot-sidecars.json 解析失败：{e}')
            files = []
        if files:
            log(f'\n[2] 启动侧车 {len(files)} 个（profile: {d.get("profile", "?")}）')
            log('    这些 .so 会在启动时被 overlay 进 APEX，缺一个就 abort boot')
            for f in files:
                rel = f.get('path', '')
                hits = resolve(root, rel, idx)
                if not hits:
                    log(f'  {BAD} {rel:<52} 包里找不到')
                    bad += 1
                elif len(hits) > 1:
                    log(f'  {WARN} {rel:<52} 找到 {len(hits)} 处，逐个校验')
                    for h in hits:
                        if check_one(h, f.get('size'), f.get('sha256'),
                                     os.path.relpath(h, root), log) == 'bad':
                            bad += 1
                else:
                    if check_one(hits[0], f.get('size'), f.get('sha256'),
                                 rel, log) == 'bad':
                        bad += 1

    # ── 构建产物 ──
    if 'build-receipt.json' in meta:
        try:
            r = json.load(open(meta['build-receipt.json'], encoding='utf-8'))
            arts = r.get('artifacts', [])
        except Exception as e:
            log(f'\n[3] build-receipt.json 解析失败：{e}')
            arts = []
        if arts:
            log(f'\n[3] 构建产物 {len(arts)} 个（这些是 VMOS 自己编译替换过的文件）')
            for a in arts:
                t = a.get('target') or a.get('name') or '?'
                sha = a.get('sha256')
                size = a.get('size')
                hits = idx.get(t, [])
                if not hits:
                    for ext in ('.so', '.jar', '.apk'):
                        hits = idx.get(t + ext, [])
                        if hits:
                            break
                if not hits:
                    log(f'  {WARN} {t:<52} 包里没找到同名文件（可能不是 ROM 内文件）')
                    continue
                if len(hits) > 1:
                    log(f'  {WARN} {t:<52} 找到 {len(hits)} 处，取第一个校验')
                if check_one(hits[0], size, sha, t, log) == 'bad':
                    bad += 1

    # ── 索引目录旁挂文件 ──
    log('\n[4] SOMV 索引目录')
    imgs, idx_dirs, idx_files = va.sniff(root)
    log(f'  镜像 {len(imgs)} 个，索引目录 {len(idx_dirs)} 个，单文件索引 {len(idx_files)} 个')
    side = 0
    for d in idx_dirs:
        try:
            names = os.listdir(d)
        except OSError:
            continue
        odd = [n for n in names
               if not (len(n) == 8 and all(c in '0123456789abcdefABCDEF' for c in n))]
        if odd:
            side += len(odd)
            log(f'  {WARN} {d} 里有 {len(odd)} 个非索引文件：'
                + ', '.join(odd[:5]) + (' …' if len(odd) > 5 else ''))
            log('       这类文件（.vmos_exec_overlay 等）是运行时旁挂数据，'
                '重打包必须原样带回去')
    if not side:
        log(f'  {OK} 索引目录里只有 8 位 hex 索引文件，没有旁挂数据')

    log('\n[5] 结论')
    if bad == 0:
        log(f'  {OK} 清单里登记的文件全部对得上 —— 你改的东西不在这份清单里，'
            f'或改动没破坏这些文件')
    else:
        log(f'  {BAD} {bad} 个登记文件缺失或被改动，启动时会在对应阶段失败：')
        log('     - 侧车 .so 缺失/改动 → [APEX-APP] flat overlay failed → abort boot')
        log('     - services.jar / SystemUI 等改动 → 可能触发单独校验或签名问题')
    return 0 if bad == 0 else 2


def main():
    ap = argparse.ArgumentParser(description='VMOS 启动前体检：核对包内清单里的文件')
    ap.add_argument('input', help='压缩包或解包目录（包根，含 root/）')
    ap.add_argument('--version', action='version', version=f'vmos_boot_audit {VERSION}')
    args = ap.parse_args()

    src = os.path.abspath(args.input)
    tmp = None
    try:
        if os.path.isdir(src):
            root = src
        else:
            tmp = tempfile.mkdtemp(prefix='boot_audit_')
            print(f'解压 {os.path.basename(src)} …')
            root = va.materialize(src, os.path.join(tmp, 'pkg'))
        code = audit(root, print)
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
    sys.exit(code)


if __name__ == '__main__':
    main()
