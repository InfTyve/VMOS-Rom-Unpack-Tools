#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vmos_7z_check.py — 检查自制的 ROM 7z 是否符合 VMOS 导入要求

VMOS 导入 ROM 时先看压缩包结构，结构不对就直接失败，且提示很笼统。
这个工具把「结构」这一层的所有硬性要求列出来逐条核：

  1. 是不是真的 7z（不是把 zip 改名）
  2. 压缩参数是否与官方一致（LZMA2、非固实、每成员独立块）
  3. 顶层必备成员是否齐全（guestOSInfo / libvmoskernel.so / 各种 json）
  4. 三个分区是否都有 .so + vblock + 索引分片
  5. 与官方包逐成员比对大小（可选 --baseline）

用法:
    python3 vmos_7z_check.py 你的.7z
    python3 vmos_7z_check.py 你的.7z --baseline 官方.7z
"""

import argparse
import os
import subprocess
import sys

VERSION = '2026.10.31.1'

OK, BAD, WARN, INFO = '\u2714', '\u2718', '\u26a0', '\u00b7'

SEVENZ_MAGIC = b'7z\xbc\xaf\x27\x1c'
ZIP_MAGIC = b'PK\x03\x04'

# VMOS 导入时会在包根目录找这些文件，缺一个就起不来
TOP_FILES = [
    'guestOSInfo',
    'libvmoskernel.so',
    'build-receipt.json',
    'boot-sidecars.json',
    'a15-plugin-profile.json',
    'romex-native.json',
    'runtime-artifacts.json',
    'vendor-runtime-artifacts.json',
    'media-artifacts.json',
    'media-build-receipt.json',
    'audio-playback-artifacts.json',
    'audio-playback-build.json',
    'browser-via-artifacts.json',
    'neutral-render-build.json',
    'kernel-plugin-protocol',
]

PROVENANCE = [
    'baseline-provenance/a15-plugin-profile.json',
    'baseline-provenance/boot-sidecars.json',
    'baseline-provenance/media-artifacts.json',
    'baseline-provenance/runtime-artifacts.json',
    'baseline-provenance/vendor-runtime-artifacts.json',
]

# Android 15 官方的分区大小，用来判断"是不是把别的分区塞进来了"
PARTITIONS = ('root/root', 'root/vendor', 'root/system')


def find_7z():
    for name in ('7z', '7za', '7zr'):
        try:
            subprocess.run([name], capture_output=True)
            return name
        except FileNotFoundError:
            continue
    return None


def seven_zip_entries(exe, path):
    """返回 (头部信息 dict, {成员路径: {Size, CRC, ...}}, 错误串)"""
    try:
        r = subprocess.run([exe, 'l', '-slt', path],
                           capture_output=True, text=True, errors='replace')
    except Exception as ex:
        return {}, {}, f'调用 {exe} 失败：{ex}'
    if r.returncode != 0:
        return {}, {}, (r.stdout or '')[-400:] + (r.stderr or '')[-400:]

    head, blocks, cur = {}, [], None
    for line in r.stdout.splitlines():
        if ' = ' not in line:
            continue
        k, v = line.split(' = ', 1)
        k, v = k.strip(), v.strip()
        if k == 'Path':
            cur = {'Path': v}
            blocks.append(cur)
        elif cur is None:
            head[k] = v            # 归档名之前的字段（极少见）
        else:
            cur[k] = v
    # 第一个块是归档自身（带 Type = 7z），不是成员
    if blocks and blocks[0].get('Type'):
        arc = blocks.pop(0)
        head.update({k: v for k, v in arc.items() if k != 'Path'})
    entries = {b['Path']: b for b in blocks}
    return head, entries, None


def human(n):
    n = float(n)
    for u in ('B', 'KB', 'MB', 'GB'):
        if abs(n) < 1024 or u == 'GB':
            return f'{n:,.0f} {u}' if u == 'B' else f'{n:,.1f} {u}'
        n /= 1024.0


def main():
    ap = argparse.ArgumentParser(description='检查 ROM 7z 是否符合 VMOS 导入结构')
    ap.add_argument('rom')
    ap.add_argument('--baseline', help='官方 7z，用于逐成员比对')
    ap.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    args = ap.parse_args()

    if not os.path.isfile(args.rom):
        sys.exit(f'文件不存在：{args.rom}')

    size = os.path.getsize(args.rom)
    problems, warns = [], []
    print(f'文件 {args.rom}  ({human(size)})')

    # ── 1. 是不是 7z ──
    print('\n【1】文件格式')
    with open(args.rom, 'rb') as f:
        magic = f.read(6)
    if magic == SEVENZ_MAGIC:
        print(f'  {OK} 真 7z（魔数 37 7A BC AF 27 1C）')
    elif magic.startswith(ZIP_MAGIC):
        print(f'  {BAD} 这是 ZIP，不是 7z —— 直接把 zip 改名成 .7z 是无效的')
        print('        VMOS 用 lib7z 打开，读到 PK\\x03\\x04 就失败')
        problems.append('文件其实是 zip')
        return 1
    else:
        print(f'  {BAD} 未知格式，开头是 {magic.hex()}')
        problems.append('格式未知')
        return 1

    exe = find_7z()
    if not exe:
        print(f'  {WARN} 找不到 7z 命令，跳过结构与参数检查')
        print('        装一个：apt install p7zip-full / brew install p7zip')
        return 0

    head, entries, err = seven_zip_entries(exe, args.rom)
    if err:
        print(f'  {BAD} 7z 打不开：{err.strip()[:300]}')
        print('        包内部结构损坏（压缩时被截断，或文件被追加过东西）')
        problems.append('7z 结构损坏')
        return 1

    # ── 2. 压缩参数 ──
    print('\n【2】压缩参数')
    method = head.get('Method', '')
    solid = head.get('Solid', '')
    blocks = head.get('Blocks', '?')
    files = [p for p, e in entries.items()
             if not (e.get('Attributes', '').startswith('D'))]
    print(f'  · Method = {method}')
    print(f'  · Solid  = {solid}    Blocks = {blocks}    成员 {len(files)} 个')
    if 'LZMA2' in method:
        print(f'  {OK} LZMA2，与官方一致')
    else:
        print(f'  {WARN} 官方是 LZMA2，你是 {method}')
        warns.append('压缩算法与官方不同')
    if solid == '-':
        print(f'  {OK} 非固实（每个成员独立块），支持随机取单个文件')
    else:
        print(f'  {BAD} 固实压缩（Solid = {solid}）')
        print('        官方是 Solid = -。固实块下取一个文件要解开整块，')
        print('        VMOS 按需取 root/system/.so 会超时或失败')
        problems.append('用了固实压缩')
    if str(blocks).isdigit() and len(files) and int(blocks) < len(files):
        print(f'  {BAD} 块数 {blocks} < 成员数 {len(files)}，说明多个文件压进了同一块')
        problems.append('块数不足')

    # ── 3. 顶层必备成员 ──
    print('\n【3】顶层必备成员')
    missing = [n for n in TOP_FILES if n not in entries]
    if missing:
        print(f'  {BAD} 缺 {len(missing)} 个：' + '、'.join(missing[:6])
              + ('…' if len(missing) > 6 else ''))
        print('        VMOS 导入时在包根目录找这些文件，缺一个就失败')
        problems.append(f'缺顶层文件 {len(missing)} 个')
    else:
        print(f'  {OK} 15 个顶层文件齐全')
    miss_pv = [n for n in PROVENANCE if n not in entries]
    if miss_pv:
        print(f'  {WARN} baseline-provenance/ 缺 {len(miss_pv)} 个')
        warns.append('provenance 不全')
    else:
        print(f'  {OK} baseline-provenance/ 5 个齐全')
    if 'system/framework/services.jar' in entries:
        print(f'  {OK} system/framework/services.jar 在')
    else:
        print(f'  {WARN} 缺 system/framework/services.jar（官方有这个文件）')
        warns.append('缺 services.jar')

    # ── 4. 分区完整性 ──
    print('\n【4】三个分区')
    for part in PARTITIONS:
        so = f'{part}/.so'
        vb = f'{part}/vblock'
        # 索引分片的文件形如 root/system/00000000/00001001，比 .so 深一层
        idx = [p for p, e in entries.items()
               if p.startswith(part + '/') and p.count('/') >= 3
               and not e.get('Attributes', '').startswith('D')]
        ok_so = so in entries
        ok_vb = vb in entries
        mark = OK if (ok_so and ok_vb and idx) else BAD
        detail = []
        detail.append(f'.so {human(int(entries[so].get("Size", 0))) if ok_so else "缺失"}')
        detail.append(f'vblock {"在" if ok_vb else "缺失"}')
        detail.append(f'索引分片 {len(idx)} 个')
        print(f'  {mark} {part:14s} ' + '  '.join(detail))
        if not (ok_so and ok_vb and idx):
            problems.append(f'{part} 不完整')

    # ── 5. 与官方逐成员比对 ──
    if args.baseline:
        print('\n【5】与官方逐成员比对')
        if not os.path.isfile(args.baseline):
            print(f'  {WARN} 找不到基线 {args.baseline}')
        else:
            bhead, bentries, berr = seven_zip_entries(exe, args.baseline)
            if berr:
                print(f'  {WARN} 基线读不了：{berr.strip()[:200]}')
            else:
                bfiles = {p: e for p, e in bentries.items()
                          if not e.get('Attributes', '').startswith('D')}
                all_new = sorted(set(entries) - set(bfiles))
                gone = sorted(set(bfiles) - set(entries))
                dirs_new = [p for p in all_new
                            if entries[p].get('Attributes', '').startswith('D')]
                new = [p for p in all_new if p not in set(dirs_new)]
                print(f'  · 官方 {len(bfiles)} 个 / 你的 {len(files)} 个')
                if gone:
                    print(f'  {BAD} 少了 {len(gone)} 个：')
                    for p in gone[:10]:
                        print(f'        - {p}  ({human(int(bfiles[p].get("Size", 0)))})')
                    if len(gone) > 10:
                        print(f'        … 还有 {len(gone) - 10} 个')
                    problems.append(f'比官方少 {len(gone)} 个成员')
                else:
                    print(f'  {OK} 官方成员一个不少')
                if dirs_new:
                    print(f'  {WARN} 多出 {len(dirs_new)} 个目录条目（官方包里没有）：')
                    for p in dirs_new[:6]:
                        print(f'        {p}/')
                    print('        这是 `7z a 目录名` 的副产物。多数解压器无害，')
                    print('        但 VMOS 的 lib7z 按成员遍历时可能当文件处理，')
                    print('        用 vmos_rom.py 直接输出 .7z 可以避免')
                    warns.append(f'{len(dirs_new)} 个目录条目')
                if new:
                    print(f'  {INFO} 多出 {len(new)} 个文件：')
                    for p in new[:8]:
                        print(f'        + {p}')
                # 大小变化（不含被改的分区镜像）
                changed = []
                for p, e in entries.items():
                    if p not in bfiles:
                        continue
                    if e.get('Size') and bfiles[p].get('Size') \
                            and e['Size'] != bfiles[p]['Size']:
                        changed.append((p, int(bfiles[p]['Size']), int(e['Size'])))
                if changed:
                    print(f'  {INFO} 大小有变化的 {len(changed)} 个：')
                    for p, a, b in changed[:10]:
                        print(f'        {p}: {human(a)} → {human(b)}')
                else:
                    print(f'  {OK} 所有同名成员大小一致')

    # ── 结论 ──
    print('\n【6】结论')
    if problems:
        print(f'  {BAD} 结构不合格，VMOS 会在导入阶段失败')
        for p in problems:
            print(f'      · {p}')
        print('\n  正确的重压方式：')
        print('    mkdir stage && cd stage')
        print('    unzip -q ../build/rom.zip          # 或 7z x ../build/rom.zip')
        print('    7z a -t7z -mx=9 -ms=off ../rom.7z ./*')
        print('    → -t7z 指定格式，-ms=off 关固实（官方就是非固实）')
        print('    → 在解包目录里用 ./* ，别写成 7z a rom.7z stage/ （会多一层目录）')
        return 1
    if warns:
        print(f'  {OK} 硬性结构通过，有 {len(warns)} 条提醒：')
        for w in warns:
            print(f'      · {w}')
    else:
        print(f'  {OK} 结构与官方一致，7z 这一层没问题')
    print('  → 若仍导入失败，问题在包内数据（catalog 的 sha256 / 镜像本身），')
    print('    用 vmos_rom_diff.py 与官方比对，或抓 logcat 看具体报错')
    return 0


if __name__ == '__main__':
    sys.exit(main())
