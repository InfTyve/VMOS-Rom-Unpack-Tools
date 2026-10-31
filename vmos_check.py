#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vmos_check.py —— 复刻 VMOS 启动前的 ROM 包校验链，逐项告诉你包坏在哪。

VMOS 的 classes.dex 里，打开 ROM 归档前会做这几件事（见 README 的分析）：

  1. 把 7z/zip 展开成目录，要求是目录（"Expanded ROM carrier is not a directory"）
  2. root/system、root/root、root/vendor 三个载体目录里必须有 .so
     （否则 "Incomplete full ROM image"）
  3. 同目录的 vblock 必须 >= 16 字节，头 4 字节 "KLBV"，紧接着 u32 = 16
     （否则 "Invalid ROM writable image header"）
  4. 归档里必须有 guestOSInfo 和 libvmoskernel.so
     （否则 "guestOSInfo not exist" / "libvmoskernel.so not exist"）
  5. guestOSInfo 里的 Android 版本、引擎类型、ABI 必须能认出来

本工具把这 5 条 + SOMV 镜像内部一致性全部跑一遍。只需要读每个镜像的前
几百 KB，2.4 GB 的 system 也是几秒钟。

用法:
  python3 vmos_check.py 新包.7z
  python3 vmos_check.py 新包.7z --orig 原包.7z      # 顺带对比成员清单
  python3 vmos_check.py 解包目录                    # 目录也行
"""
import argparse
import os
import struct
import subprocess
import sys
import zipfile

MAGIC = b'SOMV'
VBLOCK_MAGIC = b'KLBV'
DATA_ALIGN = 4096
HEAD = 64
REC = 44
IDX_NAME_LEN = 8

OK = '\u2714'
BAD = '\u2718'
WARN = '\u26a0'
INFO = '\u00b7'

VERSION = '2026.10.31.1'
BUILD_NOTE = '无索引/无 vblock 的老包不再误判 + vblock 必须与原包逐字节一致'


def human(n):
    for u in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024 or u == 'TB':
            return f'{n:,.0f} {u}' if u == 'B' else f'{n:.1f} {u}'
        n /= 1024.0


def is_core(name):
    """镜像 / 索引本来就该变，不算意外改动。

    vblock 故意不在这里：它只记 magic + 版本 + inode 数，重打包时一个字节
    都不该变。vblock 一旦被改，VM 挂 /data 会失败（[BOOT-CFS] open vblock
    FAILED），接着 apex-tmp 目录不可用、APEX 解压中断，最后 abort boot。
    """
    if name.endswith('/.so'):
        return True
    segs = name.split('/')
    if len(segs) >= 2:
        d = segs[-2]
        if len(d) == IDX_NAME_LEN and all(c in '0123456789abcdef' for c in d):
            return True
    return False


def find_7z():
    for n in ('7z', '7za', '7zr'):
        p = os.popen(f'command -v {n} 2>/dev/null').read().strip()
        if p:
            return p
    return None


class Pkg:
    """统一成「列成员 + 读某成员前 N 字节」"""

    def __init__(self, path):
        self.path = path
        self.tmp = None
        self.exe = None
        if os.path.isdir(path):
            self.kind = 'dir'
            self._members = []
            for dp, dns, fns in os.walk(path):
                rel = os.path.relpath(dp, path).replace(os.sep, '/')
                for fn in fns:
                    name = fn if rel == '.' else f'{rel}/{fn}'
                    try:
                        self._members.append(
                            (name, os.path.getsize(os.path.join(dp, fn)), False))
                    except OSError:
                        pass
                for d in dns:
                    self._members.append(
                        (d if rel == '.' else f'{rel}/{d}', 0, True))
        elif path.lower().endswith('.zip'):
            self.kind = 'zip'
            with zipfile.ZipFile(path) as z:
                self._members = [(i.filename, i.file_size, i.is_dir())
                                 for i in z.infolist()]
        else:
            self.kind = '7z'
            self.exe = find_7z()
            if not self.exe:
                raise SystemExit('需要 7z 命令来读这个包\n'
                                 '  Termux: pkg install p7zip')
            self._members = self._list_7z()

    def _list_7z(self):
        r = subprocess.run([self.exe, 'l', '-slt', '-ba', self.path],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode != 0:
            raise SystemExit('7z 读不了这个包: '
                             + r.stderr.decode('utf-8', 'replace')[:300])
        out, cur = [], {}
        for line in r.stdout.decode('utf-8', 'replace').splitlines():
            if line.startswith('Path = '):
                if cur.get('path'):
                    out.append(cur)
                cur = {'path': line[7:]}
            elif line.startswith('Size = '):
                try:
                    cur['size'] = int(line[7:])
                except ValueError:
                    cur['size'] = 0
            elif line.startswith('Folder = '):
                cur['dir'] = line[9:].strip() == '+'
            elif line.startswith('Attributes = '):
                cur['attr'] = line[13:].strip()
        if cur.get('path'):
            out.append(cur)
        res = []
        for c in out:
            name = c['path'].replace('\\', '/')
            if name == self.path or name.endswith('.7z') and '/' not in name:
                continue
            isdir = c.get('dir') or c.get('attr', '').startswith('D')
            res.append((name, c.get('size', 0), bool(isdir)))
        return res

    def members(self):
        return self._members

    def crcs(self):
        """{成员名: CRC32}，用来确认「没重建的成员一个字节都没变」"""
        if self.kind == 'dir':
            return {}
        if self.kind == 'zip':
            with zipfile.ZipFile(self.path) as z:
                return {i.filename: i.CRC for i in z.infolist() if not i.is_dir()}
        r = subprocess.run([self.exe, 'l', '-slt', '-ba', self.path],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        out, cur = {}, None
        for line in r.stdout.decode('utf-8', 'replace').splitlines():
            if line.startswith('Path = '):
                cur = line[7:].replace('\\', '/')
            elif line.startswith('CRC = ') and cur:
                try:
                    out[cur] = int(line[6:], 16)
                except ValueError:
                    pass
        return out

    def read(self, name, n):
        if self.kind == 'dir':
            with open(os.path.join(self.path, name.replace('/', os.sep)),
                      'rb') as f:
                return f.read(n)
        if self.kind == 'zip':
            with zipfile.ZipFile(self.path) as z:
                with z.open(name) as f:
                    return f.read(n)
        p = subprocess.Popen([self.exe, 'x', '-so', '-y', '-bd', '-bso0',
                              '-bsp0', self.path, name],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            return p.stdout.read(n)
        finally:
            p.kill()
            p.wait()

    def close(self):
        pass


def check_somv(pkg, mirror, size, problems, stats):
    """只看前 64B + inode 表，不读数据区"""
    head = pkg.read(mirror, HEAD)
    if len(head) < HEAD:
        problems.append(f'{mirror}: 文件太短（{len(head)} 字节），读不到 SOMV 头')
        return
    if head[:4] != MAGIC:
        problems.append(f'{mirror}: 头 4 字节是 {head[:4]!r}，不是 b\'SOMV\'')
        return
    ver, count, dlen = struct.unpack_from('<III', head, 4)
    data_start = max(DATA_ALIGN, -(-(HEAD + REC * count) // DATA_ALIGN)
                     * DATA_ALIGN)
    want = data_start + dlen
    stats['ver'] = ver
    stats['count'] = count
    stats['dlen'] = dlen
    stats['end'] = want

    if count == 0:
        problems.append(f'{mirror}: inode 数是 0')
        return
    if HEAD + REC * count > data_start:
        problems.append(f'{mirror}: inode 表 {HEAD + REC * count} 字节，'
                        f'超出数据区起点 {data_start}')
    if size and abs(size - want) > DATA_ALIGN:
        problems.append(f'{mirror}: 实际 {human(size)}，'
                        f'按头推算应为 {human(want)}（差 {human(abs(size - want))}）')

    table = pkg.read(mirror, data_start)
    if len(table) < HEAD + REC * count:
        problems.append(f'{mirror}: 只读到 {human(len(table))}，'
                        f'inode 表需要 {human(HEAD + REC * count)}')
        return

    bad_mode = bad_off = bad_size = 0
    spans = []
    root_mode = struct.unpack_from('<H', table, HEAD)[0]
    if root_mode & 0xF000 != 0x4000:
        problems.append(f'{mirror}: inode 0 的 mode=0o{root_mode:o}，'
                        f'根目录应该是目录（0o4xxxx）')
    dirs = files = links = 0
    for i in range(count):
        o = HEAD + REC * i
        mode = struct.unpack_from('<H', table, o)[0]
        size_ = struct.unpack_from('<I', table, o + 28)[0]
        off = struct.unpack_from('<I', table, o + 32)[0]
        t = mode & 0xF000
        if t == 0x4000:
            dirs += 1
            continue
        if t == 0xA000:
            links += 1
        elif t == 0x8000:
            files += 1
        else:
            bad_mode += 1
            continue
        if size_ == 0:
            continue
        if off < data_start or off + size_ > want:
            bad_off += 1
            continue
        if off % DATA_ALIGN:
            bad_off += 1
            continue
        spans.append((off, off + size_))
    if bad_mode:
        problems.append(f'{mirror}: {bad_mode} 条 inode 的 mode 不是普通文件/目录/链接')
    if bad_off:
        problems.append(f'{mirror}: {bad_off} 条 inode 的 offset 越界或没 4096 对齐')

    spans.sort()
    overlap = 0
    last = 0
    for s, e in spans:
        if s < last:
            overlap += 1
        last = max(last, e)
    if overlap:
        problems.append(f'{mirror}: 数据区有 {overlap} 处重叠')

    stats.update(dirs=dirs, files=files, links=links, spans=len(spans))


def check_index(pkg, idx_dir, count, problems):
    """索引里的 inode 必须 < count，且必须落在该分片负责的号段里

    分片目录名就是 inode 高位：00000001/ 只能放 inode >= 4096 的索引。
    这条卡住了，就不会再出现「把两片合并成一片、结果 inode >= 4096 的
    目录在系统里看不见」这种事。
    """
    pre = idx_dir + '/'
    shard = idx_dir.rsplit('/', 1)[-1]
    try:
        shard_no = int(shard, 16)
    except ValueError:
        shard_no = None
    names = [n for n, s, d in pkg.members()
             if n.startswith(pre) and not d and '/' not in n[len(pre):]]
    if not names:
        problems.append(f'{idx_dir}/: 目录是空的（没有任何索引文件）')
        return 0, 0
    bad = 0
    entries = 0
    for n in names:
        base = n[len(pre):]
        if len(base) != IDX_NAME_LEN:
            problems.append(f'{idx_dir}/{base}: 文件名不是 8 位（应是 8 位小写 hex）')
            bad += 1
            continue
        try:
            ino = int(base, 16)
        except ValueError:
            problems.append(f'{idx_dir}/{base}: 不是十六进制')
            bad += 1
            continue
        if shard_no is not None and (ino >> 12) != shard_no:
            problems.append(
                f'{idx_dir}/{base}: inode {ino} 应在 {ino >> 12:08x}/ 下，放错分片了')
            bad += 1
            continue
        if ino >= count:
            problems.append(f'{idx_dir}/{base}: inode {ino} 超出范围（共 {count} 条）')
            bad += 1
            continue
        raw = pkg.read(n, 1 << 20)
        for line in raw.decode('utf-8', 'replace').splitlines():
            if '=' not in line:
                continue
            a, b = line.rsplit('=', 1)
            try:
                int(b, 16)
                entries += 1
            except ValueError:
                problems.append(f'{idx_dir}/{base}: "{line[:40]}" 的 inode 不是 hex')
                bad += 1
    return len(names), entries


def main():
    ap = argparse.ArgumentParser(description='VMOS ROM 包启动前自检')
    ap.add_argument('pkg', help='要检查的包（.7z / .zip / 解包目录）')
    ap.add_argument('--orig', help='原包，用来对比成员清单')
    ap.add_argument('--verbose', action='store_true')
    ap.add_argument('--version', action='version',
                    version=f'vmos_check {VERSION}  ({BUILD_NOTE})')
    args = ap.parse_args()

    path = os.path.abspath(args.pkg)
    if not os.path.exists(path):
        raise SystemExit('找不到: ' + path)

    pkg = Pkg(path)
    members = pkg.members()
    total = sum(s for n, s, d in members if not d)
    print(f'包: {path}')
    print(f'     {pkg.kind}，成员 {len(members)} 个，解压后 {human(total)}')
    problems, warns = [], []

    # ── 1. 顶层结构 ──
    names = {n for n, s, d in members}
    sizes = {n: s for n, s, d in members}
    tops = sorted({n.split('/')[0] for n, s, d in members})
    print(f'\n[1] 顶层: {", ".join(tops)}')
    # 单分区包（system/.so + system/vblock）不是整 ROM，顶层检查不适用
    part_only = ('root' not in tops) and any(
        n.count('/') == 1 and n.endswith('/.so') for n in names)
    if part_only:
        print('  · 输入是单个分区包，不是整 ROM —— 跳过顶层成员检查')
    elif 'root' not in tops:
        problems.append('顶层没有 root/ 目录，VMOS 找不到 ROM 载体')

    # ── 2. guestOSInfo / libvmoskernel.so ──
    if not part_only:
        print('\n[2] 关键成员')
        for need in ('guestOSInfo',):
            hit = [n for n in names if n == need or n.endswith('/' + need)]
            if hit:
                print(f'  {OK} {need}  ({human(sizes.get(hit[0], 0))})')
            else:
                problems.append(f'归档里没有 {need}（VMOS 会报 "guestOSInfo not exist"）')
                print(f'  {BAD} 缺少 {need}')

        kv = [n for n in names if n.endswith('libvmoskernel.so')
              or n.endswith('libvmoskernel_v2.so')]
        if kv:
            for k in kv[:4]:
                print(f'  {OK} {k}  ({human(sizes.get(k, 0))})')
        else:
            problems.append('归档里没有 libvmoskernel.so（VMOS 会报同名错误）')
            print(f'  {BAD} 缺少 libvmoskernel.so')

    # ── 3. 分区 ──
    parts = []
    for n in names:
        if n.endswith('/.so'):
            d = n[:-4]
            parts.append(d)
    parts.sort()
    print(f'\n[3] 分区（<目录>/.so，vblock 可选）: {len(parts)} 个')
    if not parts:
        problems.append('一个分区都没识别到（归档里没有 <目录>/.so）')

    no_vb, no_idx = [], []
    for d in parts:
        mirror = d + '/.so'
        size = sizes.get(mirror, 0)
        print(f'\n  {d}  {human(size)}')
        vb = pkg.read(d + '/vblock', 64) if (d + '/vblock') in names else b''
        if not vb:
            # Android 7 / 更老的包不带 vblock：/data 可写层由运行时自己建
            no_vb.append(d)
            print(f'    {INFO} 没有 vblock（老包形态）')
        elif len(vb) < 16:
            problems.append(f'{d}/vblock: 只有 {len(vb)} 字节，VMOS 要求 >= 16')
            print(f'    {BAD} vblock 只有 {len(vb)} 字节')
        else:
            m1, n1 = struct.unpack_from('<II', vb, 0)
            if m1 != 0x56424C4B:      # 'KLBV' little-endian
                problems.append(f'{d}/vblock: 头 4 字节是 {vb[:4]!r}，应为 b\'KLBV\''
                                f'（VMOS 报 "Invalid ROM writable image header"）')
                print(f'    {BAD} vblock 头不对: {vb[:4]!r}')
            elif n1 != 16:
                problems.append(f'{d}/vblock: 第二个 u32 是 {n1}，VMOS 要求 16')
                print(f'    {BAD} vblock 第二个字段 {n1} != 16')
            else:
                cnt = struct.unpack_from('<I', vb, 8)[0] if len(vb) >= 12 else -1
                print(f'    {OK} vblock 头正常（KLBV + 16，count={cnt}）')

        st = {}
        check_somv(pkg, mirror, size, problems, st)
        if st.get('count'):
            print(f'    SOMV v{st["ver"]}  inode {st["count"]}  '
                  f'目录 {st.get("dirs")} / 文件 {st.get("files")} / 链接 {st.get("links")}')
            print(f'    数据区 {human(st["dlen"])}，镜像应为 {human(st["end"])}')
            if len(vb) >= 12:
                vcnt = struct.unpack_from('<I', vb, 8)[0]
                if vcnt and vcnt != st['count']:
                    problems.append(f'{d}: vblock 里 count={vcnt}，'
                                    f'镜像头里 inode={st["count"]}，两者不一致')
                    print(f'    {BAD} vblock count({vcnt}) != 镜像 inode({st["count"]})')

        pre = d + '/'
        idx_set = set()
        for n, s, dd in members:
            if not n.startswith(pre):
                continue
            rest = n[len(pre):]
            if '/' in rest:
                first = rest.split('/', 1)[0]
                if len(first) == IDX_NAME_LEN and all(
                        c in '0123456789abcdef' for c in first):
                    idx_set.add(pre + first)
        idx_dirs = sorted(idx_set)
        if not idx_dirs:
            no_idx.append(d)
            print(f'    {INFO} 没有索引目录（inode 靠镜像记录直读）')
            continue
        tot_names = tot_entries = 0
        for idir in idx_dirs:
            n, e = check_index(pkg, idir, st.get('count', 0), problems)
            tot_names += n
            tot_entries += e
        print(f'    索引 {len(idx_dirs)} 片，{tot_names} 个文件，{tot_entries} 条目录项'
              + (f'  [{", ".join(x.rsplit("/", 1)[-1] for x in idx_dirs)}]'
                 if len(idx_dirs) > 1 else ''))
        if st.get('count') and (st.get('dirs', 0) + 1) > st['count']:
            problems.append(f'{d}: 目录数超过 inode 总数')

    if no_vb:
        if len(no_vb) == len(parts):
            print(f'\n{INFO} 整包没有 vblock —— Android 7 / 更老的包本来就不带，'
                  f'不算缺陷（新版缺 vblock 才会 [BOOT-CFS] open vblock FAILED）')
        else:
            problems.append(f'{len(no_vb)} 个分区没有 vblock: ' + ', '.join(no_vb))
            print(f'{BAD} {len(no_vb)}/{len(parts)} 个分区缺 vblock（其余有）')

    if no_idx:
        if len(no_idx) == len(parts):
            print(f'\n{INFO} 整包没有索引目录 —— Android 7 / 更老的 VMOS 包就是这个形态，'
                  f'名字存在包外，不算缺陷。\n'
                  f'   解包用 vmos_auto.py（按 inode 平铺到 _recovered/），'
                  f'改完用 vmos_inode_pack.py 按 inode 回填。')
        else:
            problems.append(f'{len(no_idx)} 个分区没有索引目录: ' + ', '.join(no_idx))
            print(f'{BAD} {len(no_idx)}/{len(parts)} 个分区没有索引目录（其余有）')

    # ── 4. 与原包对比 ──
    if args.orig:
        try:
            opkg = Pkg(os.path.abspath(args.orig))
            om = {n: s for n, s, d in opkg.members() if not d}
            nm = {n: s for n, s, d in members if not d}
            miss = sorted(set(om) - set(nm))
            new = sorted(set(nm) - set(om))
            print(f'\n[4] 与原包对比: 原 {len(om)} 个成员，新 {len(nm)} 个')
            if miss:
                print(f'  {BAD} 少了 {len(miss)} 个:')
                for m in miss[:15]:
                    print(f'      - {m}  ({human(om[m])})')
                if len(miss) > 15:
                    print(f'      ... 还有 {len(miss) - 15} 个')
                problems.append(f'比原包少 {len(miss)} 个成员')
            if new:
                print(f'  {WARN} 多了 {len(new)} 个:')
                for m in new[:10]:
                    print(f'      + {m}  ({human(nm[m])})')
            if not miss and not new:
                print(f'  {OK} 成员清单完全一致')

            # vblock 是 /data 可写层的索引，必须与原包逐字节一致；
            # 改了它 VM 挂不上 /data，apex-tmp 目录跟着不可用
            vb_bad = []
            for n in sorted(set(om) & set(nm)):
                if not n.endswith('/vblock'):
                    continue
                a, b = opkg.read(n, 64), pkg.read(n, 64)
                if a != b:
                    vb_bad.append((n, a, b))
            if vb_bad:
                print(f'  {BAD} {len(vb_bad)} 个 vblock 与原包不一致:')
                for n, a, b in vb_bad[:6]:
                    ca = struct.unpack_from('<I', a, 8)[0] if len(a) >= 12 else -1
                    cb = struct.unpack_from('<I', b, 8)[0] if len(b) >= 12 else -1
                    print(f'      {n}  原 count={ca} 新 count={cb}  '
                          f'原 {len(a)}B / 新 {len(b)}B')
                problems.append(f'{len(vb_bad)} 个 vblock 与原包不一致'
                                f'（VM 会报 [BOOT-CFS] open vblock FAILED）')
            elif [n for n in set(om) & set(nm) if n.endswith('/vblock')]:
                print(f'  {OK} vblock 与原包逐字节一致')

            oc, nc = opkg.crcs(), pkg.crcs()
            if oc and nc:
                same = changed = 0
                unexpected = []
                for n in set(oc) & set(nc):
                    if oc[n] == nc[n]:
                        same += 1
                    else:
                        changed += 1
                        if not is_core(n):
                            unexpected.append(n)
                print(f'  CRC 对比: {same} 个一致，{changed} 个变化')
                if unexpected:
                    print(f'  {BAD} 有 {len(unexpected)} 个「本该原样保留」的成员内容变了:')
                    for n in unexpected[:10]:
                        print(f'      ! {n}')
                    problems.append(f'{len(unexpected)} 个非核心成员内容被改动')
                elif changed:
                    print(f'  {OK} 变化的只有镜像 / 索引（正是该变的；vblock 已单独核对）')
        except SystemExit:
            raise
        except Exception as e:
            print(f'  {WARN} 对比失败: {e}')

    # ── 结论 ──
    print('\n' + '=' * 60)
    if problems:
        print(f'{BAD} 发现 {len(problems)} 个问题:')
        for i, p in enumerate(problems, 1):
            print(f'  {i}. {p}')
        print('\n这些正是 VMOS 启动时会拒绝的地方，按顺序修即可。')
        return 1
    print(f'{OK} 全部通过，包结构满足 VMOS 的校验链。')
    print('  如果仍然启动不了，就不是包结构问题，把 logcat 里 vmos 相关的行发我。')
    return 0


if __name__ == '__main__':
    sys.exit(main())
