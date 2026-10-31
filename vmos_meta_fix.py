#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vmos_meta_fix —— 只把 inode 的 mode/uid/gid/mtime 拨回原包，不动任何内容

场景：包里除了权限位，别的都对。
    vmos_rom_diff 报「记录表 N 条有变化：mode N 条 040755 → 040700」
    这是解包目录的权限被工具/系统改过，重打包时写进了镜像。

重打包（vmos_rom.py）会自动以原包为准，但 2.6 GB 要重写一遍。
如果只想验证「是不是这几十个字节导致的」，用这个：数据区一个字节不动，
只改记录表里对应的 2~8 字节，产物除了这些字段和原包逐字节相同。

用法：
    python3 vmos_meta_fix.py 官方.7z 你的.zip -o fixed.zip
    python3 vmos_meta_fix.py 官方.7z 你的.zip --dry-run        # 只看会改什么
    python3 vmos_meta_fix.py 官方.7z 你的.zip -o fixed.zip --part system,root
"""
import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zipfile

VERSION = '2026.10.31.2'
BUILD_NOTE = ('按 inode 把 mode/uid/gid/mtime 拨回原包，数据区一个字节不动；'
              '成员 >2 GiB 时强制 zip64，未改的成员压缩流原样搬运')

OK, BAD, WARN, INFO = '\u2714', '\u2718', '\u26a0', '\u00b7'
MAGIC = b'SOMV'
HEAD, REC = 64, 44


def human(n):
    if n < 0:
        return '?'
    for u in ('B', 'KB', 'MB', 'GB'):
        if abs(n) < 1024 or u == 'GB':
            return f'{n:,.0f} {u}' if u == 'B' else f'{n:,.1f} {u}'
        n /= 1024.0
    return str(n)


class Pkg:
    """只读打开 zip / 7z / 目录"""

    def __init__(self, path):
        self.path = path
        self.kind = None
        self._zf = None
        self._tmp = None
        if os.path.isdir(path):
            self.kind = 'dir'
        elif zipfile.is_zipfile(path):
            self.kind = 'zip'
            self._zf = zipfile.ZipFile(path)
            self._tmp = tempfile.mkdtemp(prefix='vmosmeta_')
        elif self._is_7z(path):
            self.kind = '7z'
            self._tmp = tempfile.mkdtemp(prefix='vmosmeta_')
        else:
            raise SystemExit(f'认不出这个包：{path}')

    @staticmethod
    def _is_7z(path):
        try:
            with open(path, 'rb') as f:
                return f.read(6) == b'7z\xbc\xaf\x27\x1c'
        except OSError:
            return False

    def names(self):
        if self.kind == 'dir':
            out = []
            for dp, _dn, fn in os.walk(self.path):
                for f in fn:
                    out.append(os.path.relpath(os.path.join(dp, f),
                                               self.path).replace(os.sep, '/'))
            return out
        if self.kind == 'zip':
            return [i.filename for i in self._zf.infolist() if not i.is_dir()]
        out = subprocess.check_output(['7z', 'l', '-ba', '-slt', self.path],
                                      text=True, errors='replace')
        return [ln[7:] for ln in out.splitlines() if ln.startswith('Path = ')]

    def local(self, name):
        """把成员落到本地文件（zip/7z 都要，方便随机读）"""
        if self.kind == 'dir':
            return os.path.join(self.path, name)
        if self.kind == '7z':
            dst = os.path.join(self._tmp, 'm_' +
                               name.replace('/', '_').replace('.', '_'))
            if os.path.exists(dst) and os.path.getsize(dst) > 0:
                return dst
            print(f'  {INFO} 7z 解出 {name}（一次性，稍等）…', flush=True)
            subprocess.run(['7z', 'e', '-y', '-bso0', '-bd', f'-o{self._tmp}',
                            self.path, name],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            base = os.path.join(self._tmp, os.path.basename(name))
            if os.path.exists(base):
                os.replace(base, dst)
            return dst if os.path.exists(dst) else None
        # zip：解到临时
        dst = os.path.join(self._tmp, 'z_' +
                           name.replace('/', '_').replace('.', '_'))
        if os.path.exists(dst) and os.path.getsize(dst) > 0:
            return dst
        with self._zf.open(name) as f, open(dst, 'wb') as g:
            shutil.copyfileobj(f, g, 1 << 22)
        return dst

    def close(self):
        if self._zf:
            self._zf.close()
        if self._tmp:
            shutil.rmtree(self._tmp, ignore_errors=True)


def read_table(pkg, member):
    """返回 (count, data_size, [rec dict])，只读头部一小段"""
    if pkg.kind == 'zip':
        # zip 里 2.6 GB 的成员不能整个解出来再读头，直接流式读前几 MB
        try:
            with pkg._zf.open(member) as f:
                hdr = f.read(HEAD)
                if len(hdr) < HEAD or hdr[:4] != MAGIC:
                    return None
                _, count, dsz = struct.unpack_from('<III', hdr, 4)
                table = f.read(REC * count)
            return _parse(count, dsz, table)
        except KeyError:
            return None
    p = pkg.local(member)
    if not p:
        return None
    with open(p, 'rb') as f:
        hdr = f.read(HEAD)
        if len(hdr) < HEAD or hdr[:4] != MAGIC:
            return None
        _, count, dsz = struct.unpack_from('<III', hdr, 4)
        table = f.read(REC * count)
    return _parse(count, dsz, table)


def _parse(count, dsz, table):
    recs = []
    for i in range(count):
        o = REC * i
        mode, = struct.unpack_from('<H', table, o)
        uid, gid = struct.unpack_from('<HH', table, o + 4)
        mt, = struct.unpack_from('<I', table, o + 24)
        size, = struct.unpack_from('<I', table, o + 28)
        off, = struct.unpack_from('<I', table, o + 32)
        recs.append(dict(mode=mode, uid=uid, gid=gid, mtime=mt, size=size, off=off))
    return count, dsz, recs


def rewrite_so(f, patches, dst_path):
    """流式重写镜像：头和数据区原样，只改记录表里的字节

    f 是任何 file-like（普通文件或 zip 成员流），全程按块拷，内存恒定
    """
    hdr = bytearray(f.read(HEAD))
    _, count, _ = struct.unpack_from('<III', hdr, 4)
    table = bytearray(f.read(REC * count))
    for ino, m, u, g, mt in patches:
        o = REC * ino
        struct.pack_into('<H', table, o, m)
        struct.pack_into('<HH', table, o + 4, u, g)
        struct.pack_into('<I', table, o + 24, mt)
    with open(dst_path, 'wb') as w:
        w.write(hdr)
        w.write(table)
        shutil.copyfileobj(f, w, 1 << 22)


def zip_replace(src_zip, member, new_file, out_zip, level=None, log=print):
    """把 zip 里的某个成员换成新文件，其它成员按压缩流原样搬运。

    两个必须处理的点：
      1) zipfile 的 ZIP64_LIMIT 是 2 GiB - 1，不是 4 GiB。
         system/.so 有 2.44 GiB，新建 ZipInfo 的 file_size 初值是 0，
         python 就以为不需要 zip64，写满 2 GiB 后 close() 抛
         「File size too large, try using force_zip64」。必须显式 force_zip64。
      2) 原成员本身就是 zip64 写的，extra 里带着一段 0x0001（旧 size）。
         直接搬 extra 再让 python 自己加 zip64 段，会得到两段 0x0001，
         解压器可能认错。必须先剥掉。
    """
    member = member.replace('\\', '/').lstrip('/')
    tmp = out_zip + '.tmp'
    with zipfile.ZipFile(src_zip) as zin:
        infos = zin.infolist()
        hit = [i for i in infos
               if i.filename.replace('\\', '/').lstrip('/') == member]
        if not hit:
            raise SystemExit(f'包里没有 {member}')
        kw = {'allowZip64': True}
        if level is not None:
            kw['compresslevel'] = level
        with zipfile.ZipFile(tmp, 'w', **kw) as zout:
            for i in infos:
                if i.filename.replace('\\', '/').lstrip('/') == member:
                    _put_file(zout, member, i, new_file)
                else:
                    try:
                        _copy_raw(zin, zout, i)
                    except Exception as e:      # 兜底：老老实实解压再压
                        log(f'  {WARN} 原样搬运失败（{e}），回退解压重压')
                        with zin.open(i) as r, \
                                zout.open(_clone(i), 'w',
                                          force_zip64=_big(i.file_size)) as w:
                            shutil.copyfileobj(r, w, 1 << 22)
    os.replace(tmp, out_zip)


def _big(n):
    return n > zipfile.ZIP64_LIMIT


def _strip_zip64(extra):
    """剥掉 extra 里的 zip64(0x0001) 段，别的段一个字节不动"""
    out = bytearray()
    i, n = 0, len(extra or b'')
    while i + 4 <= n:
        hid, sz = struct.unpack_from('<HH', extra, i)
        if i + 4 + sz > n:
            out += extra[i:]
            return bytes(out)
        if hid != 0x0001:
            out += extra[i:i + 4 + sz]
        i += 4 + sz
    return bytes(out)


def _clone(i):
    """照原成员做一个干净的 ZipInfo（不共享 flag/CRC，避免污染源 infolist）"""
    ni = zipfile.ZipInfo(i.filename, date_time=i.date_time)
    ni.compress_type = i.compress_type
    ni.external_attr = i.external_attr
    ni.internal_attr = i.internal_attr
    ni.create_system = i.create_system
    ni.comment = i.comment
    ni.extra = _strip_zip64(i.extra)
    return ni


def _put_file(zout, name, like, path):
    """用新的本地文件替换成员；size 已知 + force_zip64 双保险"""
    size = os.path.getsize(path)
    zi = _clone(like)
    zi.filename = name
    zi.file_size = size
    with open(path, 'rb') as g, \
            zout.open(zi, 'w', force_zip64=_big(size)) as w:
        shutil.copyfileobj(g, w, 1 << 22)


def _copy_raw(zin, zout, info):
    """把成员的压缩字节原样搬过去：不解压、不重压，几 GB 也是纯拷贝。

    2.44 GiB 的 system/.so 如果重压一次要几分钟，而它多数时候根本不用改。
    """
    zi = _clone(info)
    zi.file_size = info.file_size
    zi.compress_size = info.compress_size
    zi.CRC = info.CRC

    zin.fp.seek(info.header_offset)
    lh = zin.fp.read(30)
    if len(lh) < 30 or lh[:4] != b'PK\x03\x04':
        raise RuntimeError(f'本地文件头损坏：{info.filename}')
    nlen, elen = struct.unpack_from('<HH', lh, 26)
    data_off = info.header_offset + 30 + nlen + elen

    zout._writecheck(zi)
    zi.header_offset = zout.fp.tell()
    big = _big(zi.file_size) or _big(zi.compress_size)
    zout.fp.write(zi.FileHeader(big))

    zin.fp.seek(data_off)
    left = info.compress_size
    while left > 0:
        chunk = zin.fp.read(min(left, 1 << 22))
        if not chunk:
            raise RuntimeError(f'压缩数据被截断：{info.filename}')
        zout.fp.write(chunk)
        left -= len(chunk)

    zout.filelist.append(zi)
    zout.NameToInfo[zi.filename] = zi
    zout.start_dir = zout.fp.tell()


def parts_of(names):
    return sorted({n[:-3].rstrip('/') for n in names if n.endswith('/.so')})


def main():
    ap = argparse.ArgumentParser(
        description='按 inode 把 mode/uid/gid/mtime 拨回原包（内容不动）')
    ap.add_argument('base', help='官方/原包（zip / 7z / 目录）')
    ap.add_argument('target', help='要修的包')
    ap.add_argument('-o', '--out', help='输出包；不给就只报告')
    ap.add_argument('--part', help='只处理这些分区，逗号分隔（默认全部）')
    ap.add_argument('--dry-run', action='store_true', help='只报告，不写文件')
    ap.add_argument('--level', type=int, default=None,
                    help='zip 压缩级别 0-9（默认沿用 zlib 的 6）；'
                         '0 = 不压缩，最快，包会大到 2.6 GB 以上')
    ap.add_argument('--version', action='version',
                    version=f'vmos_meta_fix {VERSION}  ({BUILD_NOTE})')
    args = ap.parse_args()

    A, B = Pkg(args.base), Pkg(args.target)
    na, nb = set(A.names()), set(B.names())
    pa, pb = parts_of(na), parts_of(nb)
    print(f'基线: {args.base}  ({A.kind})')
    print(f'目标: {args.target}  ({B.kind})')
    print(f'分区: 基线 {pa}\n      目标 {pb}')

    want = [p for p in pa if p in pb]
    if args.part:
        sel = {x.strip() for x in args.part.split(',') if x.strip()}
        want = [p for p in want
                if p.rsplit('/', 1)[-1] in sel or p in sel]
    if not want:
        raise SystemExit('两个包没有共同分区，是不是拿错文件了')

    work = tempfile.mkdtemp(prefix='vmosmeta_work_')
    todo = []
    total = 0
    for pref in want:
        member = f'{pref}/.so'
        ta = read_table(A, member)
        tb = read_table(B, member)
        if not ta or not tb:
            print(f'\n{pref}: 读不到镜像，跳过')
            continue
        ca, da, ra = ta
        cb, db, rb = tb
        print(f'\n{pref}  inode 基线 {ca} / 目标 {cb}')
        if ca != cb:
            print(f'  {BAD} inode 数不同，结构已变，这个分区不能用本工具修'
                  f'（走 vmos_rom.py 重打）')
            continue
        patches = []
        kinds = {'mode': 0, 'uid': 0, 'gid': 0, 'mtime': 0}
        examples = {}
        for i in range(ca):
            a, b = ra[i], rb[i]
            # 类型不同说明这个 inode 已经不是原来那个东西了，不动
            if (a['mode'] & 0o170000) != (b['mode'] & 0o170000):
                continue
            if (a['mode'], a['uid'], a['gid']) == (b['mode'], b['uid'], b['gid']) \
                    and a['mtime'] == b['mtime']:
                continue
            m = a['mode']
            u = a['uid'] if a['uid'] != b['uid'] else b['uid']
            g = a['gid'] if a['gid'] != b['gid'] else b['gid']
            mt = a['mtime'] if a['mtime'] != b['mtime'] else b['mtime']
            patches.append((i, m, u, g, mt))
            if a['mode'] != b['mode']:
                kinds['mode'] += 1
                examples.setdefault(('mode', a['mode'], b['mode']), 0)
                examples[('mode', a['mode'], b['mode'])] += 1
            if a['uid'] != b['uid']:
                kinds['uid'] += 1
            if a['gid'] != b['gid']:
                kinds['gid'] += 1
            if a['mtime'] != b['mtime']:
                kinds['mtime'] += 1
        if not patches:
            print(f'  {OK} 元数据逐条一致，不用改')
            continue
        print(f'  {INFO} 需要拨回 {len(patches)} 条：'
              + '，'.join(f'{k} {v}' for k, v in kinds.items() if v))
        for (k, a, b), n in sorted(examples.items(), key=lambda x: -x[1])[:4]:
            print(f'      {a:06o} → {b:06o}  {n} 条')
        if args.dry_run or not args.out:
            continue
        dst = os.path.join(work, f'{pref.replace("/", "_")}.so')
        print(f'  {INFO} 重写镜像（数据区原样拷贝）…', flush=True)
        if B.kind == 'zip':
            with B._zf.open(member) as f:
                rewrite_so(f, patches, dst)
        else:
            src = B.local(member)
            if not src:
                print(f'  {BAD} 目标包里取不出 {member}')
                continue
            with open(src, 'rb') as f:
                rewrite_so(f, patches, dst)
        todo.append((pref, member, dst))
        total += len(patches)

    if args.dry_run or not args.out:
        if total or any(True for _ in todo):
            pass
        print(f'\n{INFO} 只报告，没写文件（去掉 --dry-run 并加 -o 才会输出）')
        A.close(); B.close()
        shutil.rmtree(work, ignore_errors=True)
        return 0

    if not todo:
        print(f'\n{OK} 没有需要修的元数据')
        A.close(); B.close()
        shutil.rmtree(work, ignore_errors=True)
        return 0

    # 逐个成员替换，最后得到成品
    cur = args.target
    made = []
    for n, (pref, member, dst) in enumerate(todo):
        out = args.out if n == len(todo) - 1 else cur + f'.step{n}.zip'
        if B.kind == 'zip':
            print(f'  替换 {member}（{human(os.path.getsize(dst))}，'
                  f'其余成员原样搬运）…', flush=True)
            t0 = time.time()
            zip_replace(cur, member, dst, out, level=args.level)
            print(f'  {OK} 用时 {time.time() - t0:.1f}s')
            if out != args.out:
                made.append(out)
        elif B.kind == 'dir':
            shutil.copyfile(dst, os.path.join(B.path, member))
            out = B.path
        else:
            raise SystemExit('目标包是 7z，没法就地替换；先解压成目录或转成 zip')
        if out != cur:
            cur = out

    for f in made:                       # 中间步骤的整包副本，别留着占 2.6 GB
        try:
            os.remove(f)
        except OSError:
            pass
        print(f'  → {out}')

    print(f'\n{OK} 共拨回 {total} 条元数据，数据区一个字节没动')
    print(f'  产物：{args.out}')
    print(f'  下一步：vmos_rom_diff.py {os.path.basename(args.base)} '
          f'{os.path.basename(args.out)} 应当记录表全绿')
    A.close(); B.close()
    shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
