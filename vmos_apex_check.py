#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vmos_apex_check.py —— 启动失败定位器（APEX 阶段）

从 SOMV 镜像里直接读内容，检查 VMOS 启动最脆弱的一环：/system/apex。

背景（从 libvmoskernel.so 逆出来的启动链路）：
  [APEX-BOOT]     starting APEX bootstrap (scanning /system/apex/)...
  [APEX-TMP]      current VM extraction directory is unavailable; abort extraction
  [APEX-JAR]      cannot open APEX for %s (tried .apex/.capex in /system/apex/)
  [EXT4-RO]       mount %s: no .apex/.capex for pkg=%s

  VMOS 不用真的 apexd：它自己扫 /system/apex/*.apex 与 *.capex，
  把 javalib / lib64 / etc 提取到 apex-tmp/vmos_apex_mnt，再伪造
  apexd.status=ready+activated。任何一个 APEX 读不出来，这条链就断，
  guest 的 init 会走到 reboot，并在 /data/property 留下：
      persist.sys.boot.reason = reboot,apexd-failed

用法：
  python3 vmos_apex_check.py vmos_out/system
  python3 vmos_apex_check.py vmos_out/system --receipt build-receipt.json
  python3 vmos_apex_check.py vmos_out/            # 自动找所有分区

  --receipt 接受 vmos_out 里的 build-receipt.json（ROM 包顶层成员），
  它记录了 14 个产物的 sha256，能逐项验证镜像里的真实内容。
"""

import argparse
import hashlib
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vmos_pack as vp

OK = '\u2714'
BAD = '\u2718'
WARN = '\u26a0'

VERSION = '2026.10.31.3'
APEX_MAGIC = b'PK\x03\x04'
AVB_MAGIC = b'AVBf'
MIN_APEX = 64 * 1024          # 真实的 APEX 都在 100 KB 以上


def human(n):
    for u in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024 or u == 'TB':
            return f'{n:,.0f} {u}' if u == 'B' else f'{n:.1f} {u}'
        n /= 1024.0


# ─────────────────────────── 镜像读取 ───────────────────────────

class Vol:
    """薄封装：既能读镜像，也能回落到明文文件"""

    def __init__(self, pkg_dir):
        self.dir = pkg_dir
        self.img = None
        p = vp.find_image(pkg_dir)
        if p:
            self.img = vp.ImageReader(p)
        self.ents = vp.load_merged_ents(pkg_dir) if self.img else {}

    def rec(self, ino):
        return self.img.rec(ino) if self.img else None

    def read_range(self, ino, off, n):
        if not self.img:
            return b''
        r = self.rec(ino)
        if not r or off >= r['size']:
            return b''
        n = min(n, r['size'] - off)
        self.img.f.seek(r['off'] + off)
        return self.img.f.read(n)

    def size(self, ino):
        r = self.rec(ino)
        return r['size'] if r else 0

    def is_dir(self, ino):
        r = self.rec(ino)
        return bool(r and (r['type'] == 0o040000))

    def resolve(self, path):
        """'bin/apexd' -> inode；找不到返回 None"""
        ino = 0
        for part in [x for x in path.strip('/').split('/') if x]:
            nxt = None
            for name, child in self.ents.get(ino, []):
                if name == part:
                    nxt = child
                    break
            if nxt is None:
                return None
            ino = nxt
        return ino

    def listdir(self, ino):
        return self.ents.get(ino, [])

    def sha256(self, ino):
        h = hashlib.sha256()
        r = self.rec(ino)
        if not r:
            return None
        self.img.f.seek(r['off'])
        left = r['size']
        while left > 0:
            b = self.img.f.read(min(vp.COPY_CHUNK, left))
            if not b:
                break
            h.update(b)
            left -= len(b)
        return h.hexdigest()

    def close(self):
        if self.img:
            self.img.f.close()


class PlainVol:
    """没有镜像时的回落：直接读明文目录（接口与 Vol 一致）"""

    def __init__(self, root):
        self.dir = root
        self.img = None
        self.ents = {}

    def rec(self, p):
        return None

    def read_range(self, p, off, n):
        try:
            with open(p, 'rb') as f:
                f.seek(off)
                return f.read(n)
        except OSError:
            return b''

    def size(self, p):
        try:
            return os.path.getsize(p)
        except OSError:
            return 0

    def is_dir(self, p):
        return os.path.isdir(p)

    def resolve(self, path):
        p = os.path.join(self.dir, path.replace('/', os.sep))
        return p if os.path.exists(p) else None

    def listdir(self, p):
        try:
            return [(n, os.path.join(p, n)) for n in sorted(os.listdir(p))]
        except OSError:
            return []

    def sha256(self, p):
        h = hashlib.sha256()
        try:
            with open(p, 'rb') as f:
                while True:
                    b = f.read(vp.COPY_CHUNK)
                    if not b:
                        break
                    h.update(b)
        except OSError:
            return None
        return h.hexdigest()

    def close(self):
        pass


# ─────────────────────────── APEX 检查 ───────────────────────────

def check_apex_file(vol, ino, name, size):
    """返回 (状态, 说明)"""
    if size == 0:
        return 'empty', '0 字节'
    if size < MIN_APEX:
        return 'small', f'只有 {size} 字节，正常 APEX 至少 64 KB'

    head = vol.read_range(ino, 0, 4)
    # 先判整段为 0：数据区没写进去时，头部自然是 0，这比"不是 zip"更有诊断价值
    probe = vol.read_range(ino, 0, 4096)
    if probe and probe.count(0) == len(probe):
        return 'zero', '前 4 KB 全为 0，数据区没写入'
    if head != APEX_MAGIC:
        return 'bad-head', f'头部不是 zip（{head.hex()}），应为 504b0304'

    # 尾部 96 B 全 0 是 zipalign 到 4 KB 边界的填充，APEX 的正常形态，不当截断
    tail = vol.read_range(ino, max(0, size - 96), 96)
    if AVB_MAGIC in tail:
        return 'ok', 'zip + AVB footer'
    if tail and tail.count(0) == len(tail):
        return 'pad', 'zip 正常，尾部为对齐填充'
    return 'no-avb', 'zip 正常但没有 AVB footer'


def sample_nonzero(vol, ino, size, points=8, n=4096):
    """整段均匀采样，估算非零占比（比只看尾部可靠）"""
    if size <= 0:
        return 0.0
    nz = tot = 0
    for k in range(points):
        off = int(size * k / points)
        b = vol.read_range(ino, off, min(n, size - off))
        if not b:
            continue
        nz += len(b) - b.count(0)
        tot += len(b)
    return nz / tot if tot else 0.0


def scan_apex(vol, label, problems):
    """找 apex 目录，返回 (路径, [(名字, 大小, ino)])"""
    found = []
    for cand in ('apex', 'system/apex'):
        ino = vol.resolve(cand)
        if ino is not None and vol.is_dir(ino):
            items = []
            for name, child in vol.listdir(ino):
                if vol.is_dir(child):
                    continue
                items.append((name, vol.size(child), child))
            found.append((cand, ino, items))

    if not found:
        problems.append(f'{label}: 镜像里找不到 apex 目录（apex/ 或 system/apex/）')
        print(f'  {BAD} 找不到 apex 目录')
        return None

    cand, ino, items = found[0]
    apks = [x for x in items if x[0].endswith(('.apex', '.capex'))]
    others = [x for x in items if not x[0].endswith(('.apex', '.capex'))]

    print(f'  /{cand}: {len(items)} 个条目，其中 APEX {len(apks)} 个'
          f'（.apex {sum(1 for x in apks if x[0].endswith(".apex"))} /'
          f' .capex {sum(1 for x in apks if x[0].endswith(".capex"))}）')

    if not apks:
        problems.append(f'{label}: /{cand} 下没有任何 .apex/.capex —— '
                        f'apexd 必然失败（reboot,apexd-failed）')
        print(f'  {BAD} 一个 APEX 都没有，这正是 apexd-failed 的直接原因')
        return cand, apks

    bad = 0
    total = 0
    for name, size, child in sorted(apks):
        st, note = check_apex_file(vol, child, name, size)
        total += size
        soft = ('ok', 'no-avb', 'pad')
        mark = OK if st == 'ok' else (WARN if st in ('no-avb', 'pad') else BAD)
        if st not in soft:
            bad += 1
        print(f'    {mark} {name:<42} {human(size):>9}  {note}')

    if others:
        print(f'    （另有 {len(others)} 个非 APEX 条目：'
              f'{", ".join(x[0] for x in others[:6])}'
              f'{" ..." if len(others) > 6 else ""}）')

    print(f'    合计 {human(total)}')
    if bad:
        problems.append(f'{label}: {bad} 个 APEX 打不开或内容为空，'
                        f'apexd 会拒绝激活（要 CRC 级确认请用 vmos_apex_probe.py）')
    return cand, apks


# ─────────────────────────── build-receipt 校验 ───────────────────────────

def load_receipt(path):
    import json
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


PARTS = ('system_ext', 'system', 'vendor', 'product', 'odm')


def artifact_part_path(p):
    """从构建路径里剥出「分区名 + 分区内路径」

    注意从右往左找：AOSP 的路径是 out/target/product/generic_arm64/system/bin/x，
    左边那个 product 是 target 目录，不是分区；取第一个会把所有产物判成 product。
    """
    parts = [x for x in p.replace('\\', '/').split('/') if x]
    for i in range(len(parts) - 2, -1, -1):
        if parts[i] in PARTS:
            rest = parts[i + 1:]
            if rest:
                return parts[i], '/'.join(rest)
    return None, None


def check_receipt(vols, receipt, problems):
    arts = receipt.get('artifacts') or []
    if not arts:
        print('  （receipt 里没有 artifacts）')
        return
    ok = miss = bad = 0
    for a in arts:
        tgt = a.get('target', '?')
        want = a.get('sha256') or ''
        part, rel = artifact_part_path(a.get('path', ''))
        vol = vols.get(part)
        if not vol:
            print(f'  {WARN} {tgt:<26} 分区 {part} 不在输入里，跳过')
            miss += 1
            continue
        ino = vol.resolve(rel)
        if ino is None:
            print(f'  {BAD} {tgt:<26} 镜像里找不到 {part}/{rel}')
            bad += 1
            continue
        size = vol.size(ino)
        got = vol.sha256(ino)
        if size != a.get('size'):
            print(f'  {BAD} {tgt:<26} 大小不符 {size} != {a.get("size")}')
            bad += 1
            continue
        if got == want:
            print(f'  {OK} {tgt:<26} {human(size):>10}  sha256 匹配')
            ok += 1
        else:
            print(f'  {BAD} {tgt:<26} {human(size):>10}  sha256 不符\n'
                  f'      期望 {want[:32]}\n'
                  f'      实际 {got[:32]}')
            bad += 1
    print(f'  → 匹配 {ok}，不符 {bad}，无法检查 {miss}')
    if bad:
        problems.append(f'build-receipt: {bad} 个产物在镜像里内容不符（数据被改坏）')


# ─────────────────────────── 主流程 ───────────────────────────

ANDROID_DIRS = ('bin', 'etc', 'framework', 'lib', 'lib64', 'app',
                'priv-app', 'apex', 'build.prop', 'system')


def looks_like_partition(d):
    """有 SOMV 镜像、有 hex 索引目录，或者看起来就是 Android 分区根"""
    if vp.find_image(d):
        return True
    try:
        entries = set(os.listdir(d))
    except OSError:
        return False
    if any(len(x) == 8 and all(c in '0123456789abcdef' for c in x)
           for x in entries):
        return True
    return sum(1 for x in ANDROID_DIRS if x in entries) >= 2


def main():
    ap = argparse.ArgumentParser(
        description='检查 SOMV 镜像里的 /system/apex 与关键产物哈希',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''示例:
  python3 vmos_apex_check.py vmos_out/system
  python3 vmos_apex_check.py vmos_out/system --receipt build-receipt.json
  python3 vmos_apex_check.py vmos_out/ --receipt build-receipt.json
''')
    ap.add_argument('path', help='分区目录、解包根目录，或 ROM 包（.7z/.zip）')
    ap.add_argument('--receipt', help='build-receipt.json 路径，用来校验产物 sha256')
    ap.add_argument('--all', action='store_true', help='列出 apex 目录下的全部条目')
    ap.add_argument('--version', action='version', version=f'vmos_apex_check {VERSION}')
    args = ap.parse_args()

    problems = []
    src = os.path.abspath(args.path)
    if not os.path.isdir(src):
        raise SystemExit(f'{BAD} 只接受已解包的目录。先跑:\n'
                         f'   python3 vmos_auto.py "{args.path}" -o vmos_out')

    # 找分区
    if looks_like_partition(src):
        parts = {os.path.basename(src): src}
    else:
        parts = {}
        for name in sorted(os.listdir(src)):
            d = os.path.join(src, name)
            if os.path.isdir(d) and looks_like_partition(d):
                parts[name] = d

    if not parts:
        raise SystemExit(f'{BAD} {src} 下没找到任何分区（需要 .so 或 8 位 hex 索引目录）')

    print(f'分区 {len(parts)} 个: {", ".join(parts)}\n')

    vols = {}
    try:
        for name, d in parts.items():
            print(f'[{name}]')
            try:
                vol = Vol(d) if vp.find_image(d) else PlainVol(d)
            except Exception as e:
                print(f'  {BAD} 打不开: {e}')
                problems.append(f'{name}: 打不开')
                continue
            vols[name] = vol
            if vol.img:
                print(f'  SOMV inode {vol.img.count}  '
                      f'数据区 {human(vol.img.dsize)}  '
                      f'{len(vol.ents)} 个目录有索引')
            else:
                print(f'  无镜像，按明文目录检查（{d}）')

            if name in ('system', 'system_ext', 'product'):
                scan_apex(vol, name, problems)
            print()

        if args.receipt:
            print('[build-receipt 产物校验]')
            check_receipt(vols, load_receipt(args.receipt), problems)
            print()
    finally:
        for v in vols.values():
            v.close()

    print('=' * 60)
    if problems:
        print(f'{BAD} 发现 {len(problems)} 个问题:')
        for i, p in enumerate(problems, 1):
            print(f'  {i}. {p}')
        return 1
    print(f'{OK} APEX 与产物校验全部通过')
    print('   若仍启动失败，说明问题不在文件内容，抓 native 日志：')
    print('     logcat -d | grep -E "APEX-BOOT|APEX-TMP|APEX-JAR|MOUNT-APEX|EXECVE-APEXD"')
    return 0


if __name__ == '__main__':
    sys.exit(main())
