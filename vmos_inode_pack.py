#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vmos_inode_pack.py —— 按 inode 回填镜像（无索引 / 无文件名也能改包）

为什么需要它
------------
Android 15 的包里有 8 位 hex 索引目录，名字 → inode 的映射写在包里，
vmos_rom.py 靠它反推分区、重建镜像和索引。

Android 7 / 更老的 VMOS 包**没有索引目录**：镜像记录表 44 字节里只有
mode / uid / gid / nlink / 时间 / size / offset，没有 name，也没有父 inode。
名字只存在包里那份索引中，索引不在 = 名字永久丢失。所以老包不能走
"解包成目录树 → 重新打包"，只能走"按 inode 号原位回填"：
inode 号是镜像自己的主键，与名字无关，改内容不影响任何映射关系。

三种用法
--------
1) 回填单分区镜像
   python3 vmos_inode_pack.py system/.so 修改目录/ -o .so.new
   修改目录里放 inode_0000xxxx.扩展名（vmos_auto.py 解出来的就是这种名字），
   或者 libc.so 这类 SONAME 名 —— 后者要靠 --manifest 才能对上 inode。

2) 用清单回填（推荐，SONAME 名也能对上）
   python3 vmos_auto.py rom.zip -o out/          # 会生成 out/system_manifest.txt
   python3 vmos_inode_pack.py out/root/system/.so out/system/ \
       --manifest out/system_manifest.txt -o .so.new

3) 直接替换回原包（最保守的重打包：其它成员逐字节、逐顺序不动）
   python3 vmos_inode_pack.py out/root/system/.so out/system/ \
       --manifest out/system_manifest.txt \
       --into rom_original.zip --member root/system/.so -o rom_new.zip

对 Android 15 的意义：vmos_rom.py 会重建索引、重排成员，某些情况下
VMOS 会拒绝开机。想排除"重打包引入的差异"，就用本工具只替换目标成员，
其余（包含索引、vblock、顺序、时间戳）一个字节都不动。

输出永远附带对比摘要：哪些 inode 内容变了、大小变了、offset 变了。
"""

import argparse
import hashlib
import json
import os
import shutil
import struct
import sys
import zipfile

VERSION = '2026.10.31.2'
BUILD_NOTE = '按 inode 回填 + 单成员替换，无索引包也能改；超 2 GiB 成员强制 zip64'

MAGIC = b'SOMV'
OK, BAD, WARN, INFO = '\u2714', '\u2718', '\u26a0', '\u00b7'
HEAD = 64
REC = 44
BLOCK = 4096
MIN_DATA = 4096

S_IFMT = 0xF000
S_IFDIR = 0x4000
S_IFLNK = 0xA000


def align(x, a=BLOCK):
    return (x + a - 1) // a * a


def human(n):
    for u in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024 or u == 'TB':
            return f'{n:,.0f} {u}' if u == 'B' else f'{n:.1f} {u}'
        n /= 1024.0


# ────────────────────────────── 原镜像 ──────────────────────────────
class SrcImage:
    """只读原镜像：记录表进内存（几十万条也就几十 MB），数据区按需流式读"""

    def __init__(self, path):
        self.path = path
        self.size = os.path.getsize(path)
        self.f = open(path, 'rb')
        head = self.f.read(HEAD)
        if head[:4] != MAGIC:
            raise SystemExit(f'{path} 不是 SOMV 镜像（头 4 字节 {head[:4]!r}）')
        self.ver, count, self.data_size = struct.unpack_from('<III', head, 4)
        max_rec = (self.size - HEAD) // REC
        if count > max_rec:
            raise SystemExit(f'{path}: 头里 inode 数 {count} 超过文件可容纳的 {max_rec}')
        self.count = count
        self.data_start = max(MIN_DATA, align(HEAD + REC * count))
        self.f.seek(HEAD)
        table = self.f.read(REC * count)
        self.recs = {}
        for i in range(count):
            o = REC * i
            mode, = struct.unpack_from('<H', table, o)
            uid, gid = struct.unpack_from('<HH', table, o + 4)
            nlink, = struct.unpack_from('<I', table, o + 12)
            atime, ctime, mtime = struct.unpack_from('<III', table, o + 16)
            size, = struct.unpack_from('<I', table, o + 28)
            doff, = struct.unpack_from('<I', table, o + 32)
            self.recs[i] = {'mode': mode, 'type': mode & S_IFMT, 'uid': uid,
                            'gid': gid, 'nlink': nlink, 'atime': atime,
                            'ctime': ctime, 'mtime': mtime, 'size': size,
                            'offset': doff}

    def read_all(self, ino):
        r = self.recs[ino]
        if r['size'] == 0:
            return b''
        if r['offset'] + r['size'] > self.size:
            return None
        self.f.seek(r['offset'])
        return self.f.read(r['size'])

    def copy_into(self, ino, fp, chunk=1 << 20):
        r = self.recs[ino]
        left = r['size']
        if left == 0:
            return 0
        if r['offset'] + left > self.size:
            return None
        self.f.seek(r['offset'])
        while left > 0:
            b = self.f.read(min(chunk, left))
            if not b:
                break
            fp.write(b)
            left -= len(b)
        return r['size'] - left

    def close(self):
        try:
            self.f.close()
        except OSError:
            pass


# ────────────────────────────── 替换来源 ──────────────────────────────
def load_manifest(path):
    """vmos_auto.py 出的 *_manifest.txt： state path<TAB>size<TAB>mode [<TAB>-> target]
    也吃 --json 出的 *_manifest.json"""
    out = {}
    if path.endswith('.json'):
        rows = json.load(open(path, encoding='utf-8'))
        for r in rows:
            if r.get('inode') is not None and r.get('state') != 'dir':
                out[int(r['inode'])] = r['path'].lstrip('/')
        return out
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            parts = line.rstrip('\n').split('\t')
            head = parts[0].rstrip()
            # 第一列是 "state   /path"（空格分隔，不是 tab）
            state, _, p = head.partition(' ')
            state, p = state.strip(), p.strip()
            if not p or state in ('dir', 'link', 'no-inode'):
                continue
            ino = None
            for col in (3, 4):
                if len(parts) > col and parts[col].strip():
                    try:
                        ino = int(parts[col].strip(), 16)
                        break
                    except ValueError:
                        continue
            if ino is None:
                ino = path_ino(os.path.basename(p))
            if ino is not None:
                out[ino] = p.lstrip('/')
    return out


def path_ino(name):
    """从 inode_0000abcd.rc 这种名字里取 inode；取不到返回 None"""
    base = os.path.basename(name)
    if not base.startswith('inode_'):
        return None
    core = base[len('inode_'):].split('.')[0]
    try:
        return int(core, 16)
    except ValueError:
        return None


def scan_dir(root):
    """扫目录：inode_xxxxxxxx.* → inode 号。返回 {ino: abs_path}"""
    out = {}
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in ('__MACOSX', '.git')]
        for fn in fns:
            p = os.path.join(dp, fn)
            ino = path_ino(fn)
            if ino is not None:
                out[ino] = p.lstrip('/')
    return out


def map_by_size_and_hash(img, root, cand_inos):
    """实在没有 inode 名、也没有清单时的兜底：
    用「大小 + 内容 sha256」在原镜像里找唯一匹配，给 SONAME 名对上 inode。
    返回 {ino: path}，匹配不唯一的不猜。"""
    by_size = {}
    for ino in cand_inos:
        r = img.recs[ino]
        if r['type'] != S_IFDIR and r['size']:
            by_size.setdefault(r['size'], []).append(ino)
    out, ambiguous = {}, 0
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in ('__MACOSX', '.git')]
        for fn in fns:
            p = os.path.join(dp, fn)
            if path_ino(fn) is not None:
                continue
            try:
                sz = os.path.getsize(p)
            except OSError:
                continue
            cand = by_size.get(sz) or []
            if len(cand) != 1:
                if len(cand) > 1:
                    ambiguous += 1
                continue
            ino = cand[0]
            blob = img.read_all(ino)
            if blob is None:
                continue
            if hashlib.sha256(blob).digest() == sha256_file(p):
                out[ino] = p
    return out, ambiguous


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            h.update(b)
    return h.digest()


# ────────────────────────────── 重建镜像 ──────────────────────────────
def rebuild(img, repl, out_path, keep_missing=True, log=print):
    """按 inode 升序重排数据区。repl: {ino: 新文件路径}

    目录 inode 的数据区恒为 0 长度；符号链接按原内容（或新文件内容）写。
    keep_missing=True 时，镜像里有但目录里没有的 inode 原样搬过来 ——
    这正是老包能用的关键：改一个文件不用把整棵树凑齐。
    """
    changed = []
    plans = []
    for ino in sorted(img.recs):
        r = img.recs[ino]
        src = repl.get(ino)
        if r['type'] == S_IFDIR:
            plans.append((ino, None, 0, r))
            continue
        if src is not None:
            newsize = os.path.getsize(src)
            plans.append((ino, src, newsize, r))
            if newsize != r['size']:
                changed.append((ino, r['size'], newsize, 'resize'))
            else:
                changed.append((ino, r['size'], newsize, 'content'))
        elif keep_missing:
            plans.append((ino, None, r['size'], r))
        else:
            changed.append((ino, r['size'], 0, 'dropped'))
            plans.append((ino, None, 0, r))

    data_start = max(MIN_DATA, align(HEAD + REC * img.count))
    pos = data_start
    offs = {}
    for ino, src, size, r in plans:
        if r['type'] == S_IFDIR or size == 0:
            offs[ino] = 0
            continue
        o = align(pos)
        offs[ino] = o
        pos = o + size
    end = align(pos)
    data_size = end - data_start

    head = bytearray(HEAD)
    head[0:4] = MAGIC
    struct.pack_into('<III', head, 4, img.ver, img.count, data_size)

    recs = bytearray(REC * img.count)
    for ino, src, size, r in plans:
        o = REC * ino
        struct.pack_into('<H', recs, o + 0, r['mode'])
        struct.pack_into('<H', recs, o + 2, 0)
        struct.pack_into('<HH', recs, o + 4, r['uid'], r['gid'])
        struct.pack_into('<I', recs, o + 8, 0)
        struct.pack_into('<I', recs, o + 12, r['nlink'])
        struct.pack_into('<III', recs, o + 16, r['atime'], r['ctime'], r['mtime'])
        struct.pack_into('<I', recs, o + 28, size)
        struct.pack_into('<I', recs, o + 32, offs.get(ino, 0))
        struct.pack_into('<I', recs, o + 36, 0)
        struct.pack_into('<I', recs, o + 40, 0)

    tmp = out_path + '.tmp'
    with open(tmp, 'wb') as f:
        f.write(head)
        f.write(recs)
        cur = HEAD + REC * img.count
        if cur < data_start:
            f.seek(data_start)
            cur = data_start
        moved = 0
        for ino, src, size, r in plans:
            o = offs.get(ino, 0)
            if r['type'] == S_IFDIR or size == 0:
                continue
            if o > cur:
                f.seek(o)
                cur = o
            if src is not None:
                with open(src, 'rb') as g:
                    shutil.copyfileobj(g, f, 1 << 20)
            else:
                n = img.copy_into(ino, f)
                if n is None:
                    raise SystemExit(f'inode {ino:08x} 原数据越界，原镜像本身有问题')
                if n != size:
                    raise SystemExit(f'inode {ino:08x} 只搬了 {n}/{size} 字节')
                moved += 1
            cur += size
        f.truncate(end)
    os.replace(tmp, out_path)

    log(f'  写入 {out_path}  {human(os.path.getsize(out_path))}')
    log(f'  inode {img.count} 个，数据区 {human(data_size)}（原 {human(img.data_size)}），'
        f'原样搬运 {moved} 个，替换 {len(repl)} 个')
    return changed, data_size


def patch_inplace(img, repl, out_path, log=print):
    """大小全不变的场合：复制原镜像，按原 offset 原位覆盖。

    记录表、数据区长度、每个 inode 的 offset 全部保持原值 ——
    打出来的包与原包只差目标文件的内容，VMOS 的任何一致性校验都过得去。
    """
    bad = [(ino, img.recs[ino]['size'], os.path.getsize(p))
           for ino, p in repl.items() if os.path.getsize(p) != img.recs[ino]['size']]
    if bad:
        raise ValueError('这些 inode 大小变了，不能原位写: '
                         + ', '.join(f'{i:08x} {a}->{b}' for i, a, b in bad[:5]))
    tmp = out_path + '.tmp'
    shutil.copyfile(img.path, tmp)
    same = 0
    with open(tmp, 'r+b') as f:
        for ino, p in repl.items():
            r = img.recs[ino]
            if r['size'] == 0:
                continue
            if sha256_file(p) == hashlib.sha256(img.read_all(ino)).digest():
                same += 1
                continue
            f.seek(r['offset'])
            with open(p, 'rb') as g:
                shutil.copyfileobj(g, f, 1 << 20)
    os.replace(tmp, out_path)
    log(f'  原位写 {out_path}  {human(os.path.getsize(out_path))}  '
        f'覆盖 {len(repl) - same} 个，内容本来相同 {same} 个')
    log(f'  记录表 / offset / 数据区长度全部保持原值')
    return same


# ────────────────────────────── 替换进原包 ──────────────────────────────
def _big(n):
    # zipfile.ZIP64_LIMIT 是 2 GiB - 1，不是 4 GiB；system/.so 有 2.44 GiB
    return n > zipfile.ZIP64_LIMIT


def _strip_zip64(extra):
    """剥掉 extra 里的 zip64(0x0001) 段：原成员若是 zip64 写的，
    这段里存着旧 size，留着会和 python 新写的 zip64 段重名冲突。"""
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
    ni = zipfile.ZipInfo(i.filename, date_time=i.date_time)
    ni.compress_type = i.compress_type
    ni.external_attr = i.external_attr
    ni.internal_attr = i.internal_attr
    ni.create_system = i.create_system
    ni.comment = i.comment
    ni.extra = _strip_zip64(i.extra)
    return ni


def _copy_raw(zin, zout, info):
    """压缩流原样搬运：不解压不重压，几个 GB 也是纯拷贝"""
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
    zout.fp.write(zi.FileHeader(_big(zi.file_size) or _big(zi.compress_size)))
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


def zip_replace(src_zip, member, new_file, out_zip, log=print):
    """把 zip 里的某个成员换成新文件，其它成员逐字节、逐顺序、逐时间戳不动。

    只改目标成员这一条，是最保守的重打包方式：
    索引、vblock、成员顺序、时间戳、压缩方式全部与原包一致。
    """
    member = member.replace('\\', '/').lstrip('/')
    with zipfile.ZipFile(src_zip) as zin:
        infos = zin.infolist()
        target = None
        for i in infos:
            if i.filename.replace('\\', '/').lstrip('/') == member:
                target = i
                break
        if target is None:
            near = [i.filename for i in infos if i.filename.endswith('/.so')]
            raise SystemExit(f'包里没有 {member}；包里的镜像成员有: {near[:6]}')

        tmp = out_zip + '.tmp'
        with zipfile.ZipFile(tmp, 'w', allowZip64=True) as zout:
            for i in infos:
                if i is target:
                    size = os.path.getsize(new_file)
                    ni = _clone(i)
                    ni.filename = member
                    ni.file_size = size
                    # 关键：不 force_zip64 的话，file_size 初值/超 2 GiB 判断
                    # 会让 close() 抛 "File size too large"
                    with open(new_file, 'rb') as g, \
                            zout.open(ni, 'w', force_zip64=_big(size)) as w:
                        shutil.copyfileobj(g, w, 1 << 20)
                else:
                    try:
                        _copy_raw(zin, zout, i)
                    except Exception as e:
                        log(f'  {WARN} 原样搬运失败（{e}），回退解压重压')
                        with zin.open(i) as r, \
                                zout.open(_clone(i), 'w',
                                          force_zip64=_big(i.file_size)) as w:
                            shutil.copyfileobj(r, w, 1 << 20)
        os.replace(tmp, out_zip)
    log(f'  替换 {member} → {out_zip}（{human(os.path.getsize(out_zip))}）')


# ────────────────────────────── 主流程 ──────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description='按 inode 把改过的文件回填进 SOMV 镜像（无索引 / 无文件名也能用）',
        epilog='解包：vmos_auto.py rom.zip -o out/ ；回填：本工具 out/root/system/.so out/system/')
    ap.add_argument('mirror', help='原 SOMV 镜像（分区目录下的 .so）')
    ap.add_argument('dir', nargs='?', help='改好的目录（vmos_auto 解出来的分区目录）')
    ap.add_argument('-o', '--out', required=True, help='输出镜像')
    ap.add_argument('--manifest', action='append', default=[],
                    help='vmos_auto 出的 *_manifest.txt / .json，用来把 SONAME 名对上 inode')
    ap.add_argument('--inode', action='append', default=[],
                    help='手工指定 ino=文件，可多次，例如 --inode 12=libc.so')
    ap.add_argument('--into', help='原压缩包（zip）；配上 --member 直接把新镜像替换回去')
    ap.add_argument('--member', help='包里要替换的成员名，例如 root/system/.so')
    ap.add_argument('--drop-missing', action='store_true',
                    help='目录里没有的 inode 直接丢掉（默认原样保留，老包不要开这个）')
    ap.add_argument('--rebuild', action='store_true',
                    help='强制全量重排数据区（默认大小不变时原位覆盖，最保守）')
    ap.add_argument('--dry-run', action='store_true', help='只报告会改什么，不写文件')
    ap.add_argument('--json', action='store_true', help='摘要输出 JSON')
    ap.add_argument('--version', action='version',
                    version=f'vmos_inode_pack {VERSION}  ({BUILD_NOTE})')
    args = ap.parse_args()

    img = SrcImage(args.mirror)
    print(f'原镜像 {args.mirror}  {human(img.size)}  v{img.ver}  inode {img.count}  '
          f'数据区 {human(img.data_size)}')

    repl = {}
    cand = list(img.recs)

    if args.dir:
        if not os.path.isdir(args.dir):
            raise SystemExit(f'不是目录: {args.dir}')
        repl.update(scan_dir(args.dir))
        named = len(repl)

        # 清单补名字 → inode
        for mp in args.manifest:
            m = load_manifest(mp)
            n = 0
            for ino, p in m.items():
                q = p if os.path.isabs(p) else os.path.join(args.dir, p)
                if ino in img.recs and os.path.isfile(q) and ino not in repl:
                    repl[ino] = q
                    n += 1
            print(f'  清单 {os.path.basename(mp)}：补上 {n} 个')
            if not n and m:
                print(f'    （清单里的路径都不在磁盘上，检查 --manifest 是否指错目录）')

        # 还没对上的（SONAME 名），按「大小 + sha256」唯一匹配
        rest = [i for i in cand if i not in repl
                and img.recs[i]['type'] != S_IFDIR and img.recs[i]['size']]
        if rest:
            got, amb = map_by_size_and_hash(img, args.dir, rest)
            repl.update(got)
            if got or amb:
                print(f'  内容匹配：对上 {len(got)} 个' + (f'，{amb} 个不唯一跳过' if amb else ''))
        print(f'  目录 {args.dir}：直接认出 {named} 个，最终替换 {len(repl)} 个')

    for spec in args.inode:
        k, _, v = spec.partition('=')
        try:
            ino = int(k, 0)
        except ValueError:
            raise SystemExit(f'--inode 的 inode 号不是数字: {spec}')
        if ino not in img.recs:
            raise SystemExit(f'原镜像里没有 inode {ino:08x}')
        if not os.path.isfile(v):
            raise SystemExit(f'文件不存在: {v}')
        repl[ino] = v
        print(f'  手工：inode {ino:08x} ← {v}')

    if not repl:
        print('没有要替换的 inode —— 检查目录里是不是 inode_xxxxxxxx.* 或给了 --manifest')

    if args.dry_run:
        for ino in sorted(repl):
            r = img.recs[ino]
            ns = os.path.getsize(repl[ino])
            flag = '大小变' if ns != r['size'] else '内容变'
            print(f'  {ino:08x}  {r["size"]:>12,} → {ns:>12,}  {flag}  {repl[ino]}')
        img.close()
        return 0

    # 内容没变的先剔掉：不该为了"回填"把整棵树重写一遍
    real = {}
    for ino, p in repl.items():
        if img.recs[ino]['type'] == S_IFDIR:
            continue
        if img.recs[ino]['size'] == os.path.getsize(p) and \
                sha256_file(p) == hashlib.sha256(img.read_all(ino)).digest():
            continue
        real[ino] = p
    if len(real) != len(repl):
        print(f'  内容相同跳过 {len(repl) - len(real)} 个，真正要改 {len(real)} 个')
    if not real:
        print('  没有实际改动 —— 原镜像复制一份即可')
        shutil.copyfile(args.mirror, args.out)
        img.close()
        if args.into and args.member:
            zip_replace(args.into, args.member, args.out, args.out + '.pkg.zip')
        return 0

    same_size = all(img.recs[i]['size'] == os.path.getsize(p) for i, p in real.items())
    if same_size and not args.rebuild:
        try:
            patch_inplace(img, real, args.out)
            changed, ds = [], img.data_size
        except ValueError as e:
            print(f'  {e}')
            changed, ds = rebuild(img, real, args.out,
                                  keep_missing=not args.drop_missing)
    else:
        changed, ds = rebuild(img, real, args.out,
                              keep_missing=not args.drop_missing)
    img.close()

    if args.into:
        if not args.member:
            raise SystemExit('用 --into 时必须给 --member（包内被替换的成员名）')
        zip_replace(args.into, args.member, args.out, args.out + '.pkg.zip')

    if args.json:
        print(json.dumps([{'inode': f'{i:08x}', 'old': a, 'new': b, 'why': c}
                          for i, a, b, c in changed], ensure_ascii=False, indent=2))

    # 自检：新镜像能读、inode 数一致、数据区不越界
    chk = SrcImage(args.out)
    bad = 0
    for ino, r in chk.recs.items():
        if r['type'] == S_IFDIR or r['size'] == 0:
            continue
        if r['offset'] < chk.data_start or r['offset'] + r['size'] > \
                HEAD and r['offset'] + r['size'] > os.path.getsize(args.out):
            bad += 1
    print(f'  自检：inode {chk.count}（原 {img.count}）'
          + (f'  ⚠ {bad} 条越界' if bad else '  ✔ 数据区无越界'))
    chk.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
