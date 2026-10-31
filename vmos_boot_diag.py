#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vmos_boot_diag.py —— 把 VMOS 启动日志读成一句结论

用法
----
  adb logcat -d > logcat.txt
  python3 vmos_boot_diag.py logcat.txt
  adb logcat -d | python3 vmos_boot_diag.py -

它会做三件事
------------
1. 按 VMOS 内核自己的日志顺序还原失败链，指出**断在哪一环**；
2. 把 `[APEX-EXT] extraction incomplete: got X/Y` 的 X/Y 换算成百分比，
   区分「一个字节都没读到」（打开失败/越界）和「读了大半」（空间不够）；
3. 对每个断点给出唯一的下一条命令，不列无关项。

已知的链条（libvmoskernel_v2.so 里硬编码的字符串，顺序固定）
------------------------------------------------------------
  [BOOT-CFS] open vblock FAILED
      → /data 可写层没挂上 → apex-tmp 目录建不出来
  [APEX-TMP] current VM extraction directory is unavailable; abort extraction
      → 解压目录拿不到，直接放弃
  [APEX-EXT] host open(%s) failed: %d
      → 源文件（APEX 里的条目）打不开：errno 说明是缺文件、越界还是没权限
  [APEX-EXT] extraction incomplete: got %lld/%u (host_fd=%d)
      → 读到的字节数不足：写盘失败（ENOSPC/EDQUOT）或镜像被截断
  [APEX-JAR] abort boot
      → javalib 解不出来，abort
  persist.sys.boot.reason=reboot,apexd-failed
      → guest 侧 apexd 起不来，这是结果不是原因
"""

import os
import re
import sys

VERSION = '2026.10.31.1'
BUILD_NOTE = '日志→结论，一屏看完断在哪一环'

# (标签, 正则, 说明, 下一步)
CHAIN = [
    ('vblock', re.compile(r'\[BOOT-CFS\].*vblock', re.I),
     'vblock（/data 可写层索引）打不开或头不对',
     '把原包的 vblock 原样搬回去：vmos_inode_pack.py --into 只换镜像、不碰 vblock；'
     '并跑 vmos_check.py 新包 --orig 原包，看 vblock 是否逐字节一致'),
    ('apex-tmp', re.compile(r'\[APEX-TMP\].*unavailable', re.I),
     'VM 解压目录不可用 —— 这是整条链的根',
     '这一条几乎总是 vblock 失败的下游结果；先确认 /data 已挂起、剩余空间够'
     '（APEX javalib 解压要几百 MB）'),
    ('open-fail', re.compile(r'\[APEX-EXT\].*host open\((.+?)\) failed[: ]+(-?\d+)', re.I),
     'APEX 里的条目在宿主侧打不开',
     '看下面换算出的 errno：ENOENT=镜像里没这条；E2BIG/EINVAL=offset+size 越界；'
     'EACCES=权限。越界基本就是镜像被截断，用 vmos_check.py 看尾部对齐'),
    ('incomplete', re.compile(r'\[APEX-EXT\].*extraction incomplete:\s*got\s+(\d+)\s*/\s*(\d+)'
                              r'(?:\s*\(host_fd=(-?\d+)\))?', re.I),
     '解压不完整：读到的字节数少于预期',
     None),
    ('jar-abort', re.compile(r'\[APEX-JAR\].*abort boot', re.I),
     'javalib 解压失败，内核直接放弃开机',
     '这是结论行，不是原因；往上找第一条 APEX-TMP / APEX-EXT'),
    ('apexd', re.compile(r'apexd-failed', re.I),
     'guest 侧 apexd 没起来（boot.reason 里的结果）',
     '同上，属于结果'),
    ('snap', re.compile(r'\[BOOT-SNAP\].*Magic/Version check FAILED', re.I),
     'vblock 的 magic/版本校验没过',
     'vblock 头必须是 b"KLBV" + u32(16) + u32(inode 数) + 全 0，任何改动都会挂'),
    ('enospc', re.compile(r'ENOSPC|No space left|EDQUOT', re.I),
     '宿主存储写满',
     '清 /data 空间或换数据目录；这一步会直接导致上面那条 extraction incomplete'),
]

ERRNO = {
    1: ('EPERM', '没权限（SELinux 或 uid 不对）'),
    2: ('ENOENT', '镜像里没有这个条目 —— 索引与镜像不同批更新'),
    13: ('EACCES', '文件权限不允许读'),
    22: ('EINVAL', '参数非法：offset+size 超出镜像长度，典型是镜像被截断'),
    27: ('EFBIG', '文件超过允许大小，通常 size 字段溢出'),
    28: ('ENOSPC', '磁盘满，写不进去'),
    30: ('EROFS', '只读文件系统，解压目录被当成只读挂载'),
}


def human(n):
    for u in ('B', 'KB', 'MB', 'GB'):
        if n < 1024 or u == 'GB':
            return f'{n:,.0f} {u}' if u == 'B' else f'{n:.1f} {u}'
        n /= 1024.0


def read_lines(src):
    if src == '-':
        return sys.stdin.read().splitlines()
    with open(src, encoding='utf-8', errors='replace') as f:
        return f.read().splitlines()


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
        print(__doc__)
        return 0
    if sys.argv[1] == '--version':
        print(f'vmos_boot_diag {VERSION}  ({BUILD_NOTE})')
        return 0

    lines = read_lines(sys.argv[1])
    print(f'日志 {sys.argv[1]}  {len(lines):,} 行')

    hits = []
    for i, ln in enumerate(lines):
        for tag, rx, why, nxt in CHAIN:
            m = rx.search(ln)
            if m:
                hits.append((i, tag, ln.strip(), m, why, nxt))

    if not hits:
        print('\n没找到 VMOS 内核的日志行。')
        print('确认抓的是宿主机 logcat 且包含 vmos 进程：')
        print('  adb logcat -d | grep -Ei "vmos|apex|BOOT-CFS" | head -50')
        return 1

    order = ['vblock', 'snap', 'enospc', 'apex-tmp', 'open-fail', 'incomplete',
             'jar-abort', 'apexd']
    seen = {}
    for i, tag, ln, m, why, nxt in hits:
        seen.setdefault(tag, []).append((i, ln, m))

    print('\n命中环节（按因果顺序排，不是日志顺序）')
    root = None
    for tag in order:
        if tag not in seen:
            continue
        i, ln, m = seen[tag][0]
        why = next(w for t, _, w, _ in CHAIN if t == tag)
        nxt = next(n for t, _, _, n in CHAIN if t == tag)
        count = len(seen[tag])
        print(f'\n  [{tag}] {why}' + (f'（出现 {count} 次）' if count > 1 else ''))
        print(f'    {ln[:150]}')

        if tag == 'incomplete':
            got, want = int(m.group(1)), int(m.group(2))
            pct = 100.0 * got / want if want else 0
            print(f'    → 拿到 {got:,} / {want:,} B（{pct:.1f}%），'
                  f'缺 {want - got:,} B（{human(want - got)}）')
            if got == 0:
                print('    → 一个字节都没读到：源文件打不开，或 offset 已经越界')
                nxt = ('镜像与索引不是同一批产物。用 vmos_check.py 查 '
                       'inode offset+size 是否越界；重打包请用 vmos_inode_pack.py '
                       '只替换目标成员，不要再重建索引')
            elif pct > 95:
                print('    → 只差尾巴：几乎一定是写到一半空间不够，或尾部没补齐 4096')
                nxt = ('查 /data 剩余空间（要留出解压体积的 1.5 倍）；'
                       '并用 vmos_check.py 确认镜像末尾补到 4096')
            else:
                print('    → 读了一部分就断：镜像在中间被截断，或该 inode 的数据区不连续')
                nxt = ('这个 inode 的 size 大于实际可读长度，用 vmos_apex_probe.py '
                       '对同一个 APEX 单独验一遍')
        if tag == 'open-fail':
            err = int(m.group(2))
            name, desc = ERRNO.get(abs(err), ('?', '未知'))
            print(f'    → errno {err} {name}：{desc}')
            if name == 'EINVAL':
                nxt = '镜像被截断或 offset 越界；用 vmos_check.py 看尾部是否补齐 4096'
            elif name == 'ENOENT':
                nxt = '索引引用了镜像里不存在的 inode；索引和镜像要同批生成'

        print(f'    下一步：{nxt}')
        if root is None and tag in ('vblock', 'snap', 'apex-tmp'):
            root = tag

    print('\n' + '=' * 62)
    if root in ('vblock', 'snap'):
        print('结论：卡在 /data 可写层。vblock 是重打包时最容易被动坏的文件 ——')
        print('      它只有 16 字节头，却决定 VM 能不能挂 /data；挂不上则 apex-tmp')
        print('      目录不可用，后面所有 APEX 报错都是它的下游。')
        print('      修法：vmos_inode_pack.py --into 原包 --member <分区>/.so，')
        print('            vblock 一个字节都不动。')
    elif root == 'apex-tmp':
        print('结论：解压目录建不出来。先确认设备上 /data 有空间、目录可写；')
        print('      若原包在同设备也这样，就是环境问题，不是包的问题。')
    elif 'incomplete' in seen or 'open-fail' in seen:
        print('结论：APEX 解压时读不全源文件 —— 镜像与索引不同批，或镜像被截断。')
        print('      先跑 vmos_check.py 新包 --orig 原包，重点看 vblock 与尾部对齐。')
    else:
        print('结论：日志里只有结果行（apexd-failed / abort boot），没抓到原因行。')
        print('      重抓一份：adb logcat -d | grep -Ei "APEX|BOOT-CFS|vmos" > log.txt')
    return 0


if __name__ == '__main__':
    sys.exit(main())
