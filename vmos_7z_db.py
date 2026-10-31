#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vmos_7z_db.py — 把 zip / 固实 7z 重打包成 VMOS 能导入的非固实 7z

VMOS 导入 ROM 时要求压缩包满足：
  · 真 7z 格式（不是 zip 改名）
  · 非固实（Solid = -），每个成员独立块，能随机取 root/system/.so
  · 块数 = 成员数
  · 没有目录条目

直接用 `7z a -t7z rom.7z root/` 打出来的包默认是固实的，块数远小于
成员数，VMOS 会在导入阶段直接失败。这个脚本负责：

  解压源包 → 只把「文件」列进 listfile → 7z a -t7z -ms=off → 自检

自检会逐成员比对大小和 CRC32，确认解压再压缩没弄坏内容。

用法:
    python3 vmos_7z_db.py rom.zip
    python3 vmos_7z_db.py rom.zip -o rom_fixed.7z --level 5
    python3 vmos_7z_db.py 已固实的.7z -o fixed.7z
    python3 vmos_7z_db.py rom.zip --baseline 官方.7z
    python3 vmos_7z_db.py rom/ -o rom.7z          # 目录也行

空间：解压要一份原始大小（官方 Android 15 约 2.7 GB），输出再一份。
     默认临时目录放在输出包同目录，可用 --workdir 指到别的盘。
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

VERSION = '2026.10.31.1'
BUILD_NOTE = '非固实 + 无目录条目 + 逐成员 CRC 自检'

OK, BAD, WARN, INFO = '\u2714', '\u2718', '\u26a0', '\u00b7'

SEVENZ_MAGIC = b'7z\xbc\xaf\x27\x1c'
ZIP_MAGIC = b'PK\x03\x04'

# 丢了就起不来的顶层文件
TOP_FILES = [
    'guestOSInfo', 'libvmoskernel.so', 'build-receipt.json',
    'boot-sidecars.json', 'a15-plugin-profile.json', 'romex-native.json',
    'runtime-artifacts.json', 'vendor-runtime-artifacts.json',
    'media-artifacts.json', 'media-build-receipt.json',
    'audio-playback-artifacts.json', 'audio-playback-build.json',
    'browser-via-artifacts.json', 'neutral-render-build.json',
    'kernel-plugin-protocol',
]


def human(n):
    n = float(n)
    for u in ('B', 'KB', 'MB', 'GB'):
        if abs(n) < 1024 or u == 'GB':
            return f'{n:,.0f} {u}' if u == 'B' else f'{n:,.1f} {u}'
        n /= 1024.0


def find_7z():
    for name in ('7z', '7za', '7zr'):
        if shutil.which(name):
            return name
    return None


def parse_7z(exe, path):
    """返回 (归档头部属性, {成员路径: {Size, CRC, ...}})"""
    r = subprocess.run([exe, 'l', '-slt', path],
                       capture_output=True, text=True, errors='replace')
    if r.returncode != 0:
        msg = ((r.stdout or '')[-300:] + (r.stderr or '')[-300:]).strip()
        raise SystemExit(f'读不了 {path}：{msg}')
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
            head[k] = v
        else:
            cur[k] = v
    if blocks and blocks[0].get('Type'):
        arc = blocks.pop(0)             # 第一块是归档自身
        head.update({k: v for k, v in arc.items() if k != 'Path'})
    return head, {b['Path']: b for b in blocks}


def zip_index(path):
    """{成员: (size, crc32)}，目录条目不算"""
    idx = {}
    with zipfile.ZipFile(path) as z:
        for i in z.infolist():
            if i.is_dir() or i.filename.endswith('/'):
                continue
            idx[i.filename] = (i.file_size, i.CRC)
    return idx


def arch_index(exe, path):
    """从 7z 里取 {成员: (size, crc)}"""
    _head, entries = parse_7z(exe, path)
    idx = {}
    for p, e in entries.items():
        if e.get('Attributes', '').startswith('D'):
            continue
        try:
            size = int(e.get('Size', '0'))
        except ValueError:
            size = 0
        crc = e.get('CRC')
        idx[p] = (size, int(crc, 16) if crc else None)
    return idx


def disk_free(path):
    p = path
    while p and not os.path.exists(p):
        p = os.path.dirname(p)
    try:
        return shutil.disk_usage(p or '.').free
    except OSError:
        return 1 << 62


def check_space(need, workdir, force):
    free = disk_free(workdir)
    print(f'  {INFO} 临时目录 {workdir} 可用 {human(free)}，'
          f'需要约 {human(need)}')
    if free < need and not force:
        raise SystemExit(
            f'\n空间不够：还差 {human(need - free)}。\n'
            f'  换个盘：--workdir /path/to/big/disk\n'
            f'  或者清一下再试（--force 可强行继续，但会中途写失败）')


def collect_files(root):
    out = []
    for dp, _dn, fns in os.walk(root):
        for fn in fns:
            if fn.endswith('.vmostmp'):
                continue
            full = os.path.join(dp, fn)
            out.append(os.path.relpath(full, root).replace(os.sep, '/'))
    out.sort()
    return out


def extract(exe, src, dest):
    cmd = [exe, 'x', '-y', f'-o{dest}']
    cmd += ['-bsp1'] if sys.stdout.isatty() else ['-bso0', '-bsp0']
    cmd.append(src)
    t0 = time.time()
    r = subprocess.run(cmd, stdout=None if sys.stdout.isatty() else subprocess.DEVNULL,
                       stderr=subprocess.PIPE)
    if r.returncode != 0:
        msg = r.stderr.decode('utf-8', 'replace').strip()
        raise SystemExit(f'解压失败（{r.returncode}）：{msg[:400]}')
    return time.time() - t0


def pack(exe, src_dir, out, level, solid=False, dict_size='256k'):
    files = collect_files(src_dir)
    if not files:
        raise SystemExit('解压目录里没有文件，源包是空的？')
    listfile = os.path.join(src_dir, '.vmos_7zdb_list.txt')
    with open(listfile, 'w', encoding='utf-8', newline='\n') as f:
        for x in files:
            f.write(x + '\n')
    if os.path.exists(out):
        os.remove(out)
    cmd = [exe, 'a', '-t7z', f'-mx={max(0, min(9, level))}', '-y']
    # 必须显式 -m0=lzma2 + -mf=off：
    # 7-Zip 23.00 起会对 ARM64 ELF（.so）自动挂 ARM64 BCJ 过滤器，出包变成
    # 「ARM64 LZMA2:18」，而手机里的 lib7z 多是老版 p7zip，不认这个过滤器，
    # 解压直接报 Unsupported method。官方包是纯 LZMA2:18。
    cmd.append('-m0=lzma2')
    cmd.append('-mf=off')
    if dict_size and dict_size != 'auto':
        cmd.append(f'-md={dict_size}')
    cmd += ['-bsp1'] if sys.stdout.isatty() else ['-bso0', '-bsp0']
    cmd.append('-ms=on' if solid else '-ms=off')   # 关键：默认非固实
    cmd += [out, '@' + listfile]
    t0 = time.time()
    r = subprocess.run(cmd, cwd=src_dir,
                       stdout=None if sys.stdout.isatty() else subprocess.DEVNULL,
                       stderr=subprocess.PIPE)
    try:
        os.remove(listfile)
    except OSError:
        pass
    if r.returncode != 0:
        msg = r.stderr.decode('utf-8', 'replace').strip()
        raise SystemExit(f'7z 打包失败（{r.returncode}）：{msg[:400]}')
    return len(files), time.time() - t0


def verify(out, src_idx, files_n, baseline):
    """返回问题列表；顺带把关键指标打印出来"""
    problems = []
    with open(out, 'rb') as f:
        magic = f.read(6)
    if magic == SEVENZ_MAGIC:
        print(f'  {OK} 真 7z（37 7A BC AF 27 1C）')
    elif magic == ZIP_MAGIC:
        print(f'  {BAD} 输出是 zip，不是 7z')
        return ['输出格式不对']
    else:
        print(f'  {BAD} 魔数不对：{magic.hex(" ")}')
        return ['输出格式不对']

    exe = find_7z()
    head, entries = parse_7z(exe, out)
    files = [p for p, e in entries.items()
             if not e.get('Attributes', '').startswith('D')]
    dirs = [p for p in entries if p not in files]
    solid = head.get('Solid', '?')
    blocks = head.get('Blocks', '?')
    method = head.get('Method', '?')
    print(f'  {INFO} Method = {method}   Solid = {solid}   '
          f'Blocks = {blocks}   成员 {len(files)} 个')

    if solid == '-':
        print(f'  {OK} 非固实：每个成员独立块，可随机取单个文件')
    else:
        print(f'  {BAD} 仍是固实压缩（Solid = {solid}）')
        problems.append('solid')

    up = (method or '').upper()
    filt = [x for x in ('ARM64', 'BCJ', 'X86', 'ARMT', 'PPC', 'SPARC', 'IA64')
            if x in up]
    if filt:
        print(f'  {BAD} 带了 {filt[0]} 过滤器（{method}），'
              f'手机上的老 p7zip 解不了')
        print('        → 用 -m0=lzma2 重新打，别让 7z 自动加 BCJ')
        problems.append('filter')
    else:
        print(f'  {OK} 纯 LZMA2，没有 BCJ 过滤器（官方同款）')

    if str(blocks).isdigit() and len(files) and int(blocks) < len(files):
        print(f'  {BAD} 块数 {blocks} < 成员 {len(files)}')
        problems.append('blocks')
    elif str(blocks).isdigit() and int(blocks) == len(files):
        print(f'  {OK} 块数 {blocks} = 成员 {len(files)}，一文件一块')

    if dirs:
        print(f'  {WARN} 有 {len(dirs)} 个目录条目：' + '、'.join(dirs[:4]))
        problems.append('dirs')
    else:
        print(f'  {OK} 没有目录条目')

    if files_n and len(files) != files_n:
        print(f'  {BAD} 成员数 {len(files)} ≠ 源 {files_n}')
        problems.append('count')
    elif files_n:
        print(f'  {OK} 成员数与源一致（{files_n}）')

    # 逐成员比对：名字、大小、CRC32
    if src_idx:
        miss = sorted(set(src_idx) - set(files))
        extra = sorted(set(files) - set(src_idx))
        if miss:
            print(f'  {BAD} 少了 {len(miss)} 个：' + '、'.join(miss[:4]))
            problems.append('missing')
        if extra:
            print(f'  {BAD} 多了 {len(extra)} 个：' + '、'.join(extra[:4]))
            problems.append('extra')
        bad = []
        for p in sorted(set(src_idx) & set(files)):
            s_size, s_crc = src_idx[p]
            e = entries[p]
            try:
                o_size = int(e.get('Size', '0'))
            except ValueError:
                o_size = -1
            o_crc = e.get('CRC')
            o_crc = int(o_crc, 16) if o_crc else None
            if o_size != s_size or (s_crc and o_crc and o_crc != s_crc):
                bad.append((p, s_size, o_size))
        if bad:
            print(f'  {BAD} {len(bad)} 个成员内容不一致：')
            for p, a, b in bad[:6]:
                print(f'        {p}  源 {human(a)} / 输出 {human(b)}')
            problems.append('content')
        else:
            print(f'  {OK} {len(src_idx)} 个成员大小 + CRC32 全部一致')

    # 顶层必备
    names = set(files)
    missing_top = [n for n in TOP_FILES if n not in names]
    if missing_top:
        print(f'  {WARN} 顶层缺 {len(missing_top)} 个：'
              + '、'.join(missing_top[:5]))
    else:
        print(f'  {OK} 15 个顶层文件齐全')

    if baseline and os.path.isfile(baseline):
        _bh, bent = parse_7z(exe, baseline)
        bset = {p for p, e in bent.items()
                if not e.get('Attributes', '').startswith('D')}
        gone = sorted(bset - names)
        add = sorted(names - bset)
        print(f'\n  与官方对比：官方 {len(bset)} / 你的 {len(names)}')
        if gone:
            print(f'  {BAD} 比官方少 {len(gone)} 个：' + '、'.join(gone[:5]))
            problems.append('vs_baseline')
        else:
            print(f'  {OK} 官方成员一个不少')
        if add:
            print(f'  {INFO} 多出 {len(add)} 个：' + '、'.join(add[:5]))
    return problems


def check_with_tool(out, baseline):
    """如果同目录有 vmos_7z_check.py，跑一遍完整检查（只显示【2】【6】）"""
    here = os.path.dirname(os.path.abspath(__file__))
    tool = os.path.join(here, 'vmos_7z_check.py')
    if not os.path.isfile(tool):
        return
    cmd = [sys.executable, tool, out]
    if baseline:
        cmd += ['--baseline', baseline]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    except Exception:
        return
    txt = r.stdout or ''
    seg = []
    for tag in ('\u30102\u3011', '\u30106\u3011'):
        if tag in txt:
            part = txt.split(tag, 1)[1]
            part = part.split('\u3010', 1)[0]
            seg.append(tag + part.rstrip())
    if seg:
        print('\n' + '\n\n'.join(seg))


def main():
    try:
        sys.stdout.reconfigure(line_buffering=True)   # 重定向到文件时也能实时看
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser(
        description='把 zip / 固实 7z 重打包成 VMOS 能导入的非固实 7z',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''示例:
  python3 vmos_7z_db.py rom.zip
  python3 vmos_7z_db.py rom.zip -o build/rom.7z --level 5
  python3 vmos_7z_db.py 固实的.7z -o 修的.7z
  python3 vmos_7z_db.py rom/ -o rom.7z --workdir /data/tmp
  python3 vmos_7z_db.py rom.zip --baseline 官方/android15_user_20008.7z
''')
    ap.add_argument('src', help='源包（.zip / .7z）或已解开的目录')
    ap.add_argument('-o', '--out', help='输出 .7z（默认 <源名>_fixed.7z）')
    ap.add_argument('--level', type=int, default=5,
                    help='7z 压缩级别 0-9，默认 5（0 = 只存储，最快但包大一倍）')
    ap.add_argument('--dict', default='256k',
                    help='LZMA2 字典大小，默认 256k（官方就是 LZMA2:18）；'
                         'auto = 按级别自动（更大字典、包小 10%%、慢一倍）')
    ap.add_argument('--solid', action='store_true',
                    help='强行固实压缩（VMOS 导入会失败，除非你就是要试）')
    ap.add_argument('--workdir', help='解压用的临时目录（默认在输出包旁边）')
    ap.add_argument('--keep-temp', action='store_true', help='保留解压目录')
    ap.add_argument('--baseline', help='官方 7z，用于逐成员比对')
    ap.add_argument('--force', action='store_true', help='空间不够也继续')
    ap.add_argument('--no-check', action='store_true',
                    help='不调用 vmos_7z_check.py 做完整检查')
    ap.add_argument('--version', action='version',
                    version=f'vmos_7z_db {VERSION}  ({BUILD_NOTE})')
    args = ap.parse_args()

    exe = find_7z()
    if not exe:
        raise SystemExit('找不到 7z 命令。\n'
                         '  Termux: pkg install p7zip\n'
                         '  Debian/Ubuntu: apt install p7zip-full\n'
                         '  macOS: brew install p7zip')

    src = os.path.abspath(args.src)
    if not os.path.exists(src):
        raise SystemExit('找不到：' + src)

    src_size = 0 if os.path.isdir(src) else os.path.getsize(src)
    out = os.path.abspath(args.out or
                          (os.path.splitext(src)[0] + '_fixed.7z'))
    if os.path.splitext(out)[1].lower() != '.7z':
        raise SystemExit(f'输出必须是 .7z，你给的是 {os.path.basename(out)}\n'
                         f'  例如: -o rom.7z')
    if not os.path.isdir(src) and out == src:
        raise SystemExit('输出和输入是同一个文件，换个名字')
    os.makedirs(os.path.dirname(out) or '.', exist_ok=True)

    print(f'源 {src}  ({human(src_size)})')
    print(f'输出 {out}')

    # ── 读源清单 ──
    src_idx, unpack_size = {}, 0
    if os.path.isdir(src):
        print(f'  {INFO} 目录源，跳过解压')
        files_n = len(collect_files(src))
        unpack_size = sum(os.path.getsize(os.path.join(dp, fn))
                          for dp, _dn, fns in os.walk(src)
                          for fn in fns if not fn.endswith('.vmostmp'))
    else:
        low = src.lower()
        if low.endswith('.zip'):
            src_idx = zip_index(src)
        elif low.endswith('.7z'):
            src_idx = arch_index(exe, src)
        else:
            raise SystemExit('只认 .zip / .7z / 目录，你给的是 '
                             + os.path.splitext(src)[1])
        files_n = len(src_idx)
        unpack_size = sum(v[0] for v in src_idx.values())
        print(f'  {INFO} 源有 {files_n} 个成员，解开约 {human(unpack_size)}')

    workdir = os.path.abspath(args.workdir) if args.workdir else \
        (os.path.dirname(out) or '.')
    os.makedirs(workdir, exist_ok=True)
    need = unpack_size + max(src_size, int(unpack_size * 0.5)) + (200 << 20)
    check_space(need, workdir, args.force)

    tmp = tempfile.mkdtemp(prefix='vmos7zdb_', dir=workdir)
    stage = tmp
    try:
        print('\n【1】解压')
        if os.path.isdir(src):
            print(f'  {INFO} 用目录本身：{src}')
            stage = src
        else:
            t = extract(exe, src, tmp)
            got = collect_files(tmp)
            print(f'  {OK} {len(got)} 个文件，用时 {t:.0f}s')
            if len(got) != files_n:
                print(f'  {WARN} 解出 {len(got)} 个，源清单 {files_n} 个'
                      f'（目录条目不计）')

        print('\n【2】打包')
        mode = '固实' if args.solid else '非固实'
        print(f'  7z a -t7z -mx={args.level} -m0=lzma2 -md={args.dict} -ms='
              f'{"on" if args.solid else "off"}（{mode}），只列文件不列目录')
        n, t = pack(exe, stage, out, args.level, args.solid, args.dict)
        ratio = (src_size / os.path.getsize(out)) if src_size and \
            os.path.getsize(out) else 0
        print(f'  {OK} {n} 个成员 → {os.path.getsize(out) and human(os.path.getsize(out))}'
              + (f'（源 {human(src_size)} 的 {ratio:.2f}×）' if ratio else '')
              + f'，用时 {t:.0f}s')

        print('\n【3】自检')
        problems = verify(out, src_idx, files_n, args.baseline)

        print('\n【4】结论')
        if problems:
            print(f'  {BAD} 还有问题：' + '、'.join(problems))
            print('  → 把上面输出发我')
            return 1
        print(f'  {OK} 结构合格：非固实、块数 = 成员数、内容逐成员一致')
        print(f'  → 可以替换进 APK 的 assets/roms/，'
              f'记得同步 catalog.json 的 size 和 sha256')

        if not args.no_check:
            check_with_tool(out, args.baseline)
        return 0
    finally:
        if not args.keep_temp and stage != src:
            shutil.rmtree(stage, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
