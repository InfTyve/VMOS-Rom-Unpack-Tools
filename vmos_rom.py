#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vmos_rom.py —— 把改过的分区直接重打包回整个 ROM 大包
================================================================

    python3 vmos_rom.py android15_user_20008.7z 解包根/ -o rom_new.zip
    python3 vmos_rom.py rom.7z 解包根/ --only system,vendor -o rom_new.zip
    python3 vmos_rom.py rom.7z 解包根/ --map vendor=D:/work/vendor -o new.zip
    python3 vmos_rom.py rom.7z 解包根/ --list          # 只看识别到什么

和 vmos_pack.py 的分工：
  vmos_pack.py  打「单个分区」→ vendor/{.so,vblock,00000000/}，要自己盖回原包
  vmos_rom.py   打「整个大包」→ 原包里 system/vendor 一起换掉，直接产出可用的大 zip

原包里其它成员（别的分区、boot.img、配置文件…）原样流式拷贝，不重新生成，
不改压缩方式以外的东西。重建的分区按原路径就地替换。

依赖同目录的 vmos_pack.py（复用扫描、索引、继承、校验）。
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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vmos_pack as vp          # noqa: E402

VERSION = '2026.10.31.2'
BUILD_NOTE = '权限/属主一律以原包为准 + _recovered 丢数据告警 + 打包后提示同步 sidecar'
COPY_CHUNK = 1 << 20
IDX_RE = vp.IDX_NAME_RE
# zipfile 内部 ZIP64_LIMIT = 2^31-1；超过它必须走 ZIP64 头，否则 close 时抛错
ZIP64_LIMIT = (1 << 31) - 1


# ────────────────────────────── 小工具 ──────────────────────────────
def human(n):
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024 or unit == 'TB':
            return f'{n:,.0f} {unit}' if unit == 'B' else f'{n:.1f} {unit}'
        n /= 1024.0


def is_hex_dir(name):
    return bool(IDX_RE.match(name))


def open_source(path, workdir):
    """把 7z / zip / 目录统一成「能按名字流式读 + 有成员清单」的对象。

    7z 先整体解到 workdir，因为 7z 无法随机访问单个成员，
    而重建分区需要读原镜像的 inode 表、原索引、原明文。
    返回 (source, 临时目录或 None)。
    """
    path = os.path.abspath(path)
    if os.path.isdir(path):
        return DirSource(path), None

    low = path.lower()
    if low.endswith(('.7z', '.xz', '.tar', '.tgz', '.bz2', '.gz')):
        exe = shutil.which('7z') or shutil.which('7za') or shutil.which('7zr')
        if not exe:
            raise SystemExit('需要 7z 命令来解包 ' + os.path.basename(path)
                             + '\n  Termux: pkg install p7zip')
        dest = tempfile.mkdtemp(prefix='romsrc_', dir=workdir)
        print(f'解压原包 → {dest}')
        t0 = time.time()
        r = subprocess.run([exe, 'x', '-y', '-bd', '-bso0', '-bsp0',
                            f'-o{dest}', path],
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        if r.returncode != 0:
            msg = r.stderr.decode('utf-8', 'replace').strip()
            raise SystemExit(f'7z 解压失败（{r.returncode}）: {msg[:400]}')
        print(f'  完成，用时 {time.time() - t0:.0f}s')
        return DirSource(dest), dest

    return ZipSource(path), None


class DirSource:
    """已解开的目录"""

    def __init__(self, root):
        self.root = root
        self.kind = 'dir'
        self._cache = None

    def members(self):
        if self._cache is not None:
            return self._cache
        out = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames.sort()
            rel = os.path.relpath(dirpath, self.root).replace(os.sep, '/')
            for fn in sorted(filenames):
                name = fn if rel == '.' else f'{rel}/{fn}'
                try:
                    size = os.path.getsize(os.path.join(dirpath, fn))
                except OSError:
                    continue
                out.append((name, size))
        self._cache = out
        return out

    def open(self, name):
        return open(os.path.join(self.root, name.replace('/', os.sep)), 'rb')

    def head(self, name, n=4):
        try:
            with self.open(name) as f:
                return f.read(n)
        except OSError:
            return b''

    def close(self):
        pass


class ZipSource:
    """zip 包，成员按 storage 顺序"""

    def __init__(self, path):
        self.path = path
        self.kind = 'zip'
        self.zf = zipfile.ZipFile(path)
        self._cache = [(i.filename, i.file_size) for i in self.zf.infolist()
                       if not i.is_dir()]

    def members(self):
        return self._cache

    def open(self, name):
        return self.zf.open(name)

    def head(self, name, n=4):
        try:
            with self.zf.open(name) as f:
                return f.read(n)
        except (OSError, KeyError, zipfile.BadZipFile):
            return b''

    def info(self, name):
        return self.zf.getinfo(name)

    def close(self):
        self.zf.close()


# ────────────────────────────── 分区识别 ──────────────────────────────
class Part:
    __slots__ = ('rel', 'mirror', 'vblock', 'idx_dirs', 'has', 'mod_dir',
                 'plan', 'done', 'mirror_size')

    def __init__(self, rel):
        self.rel = rel            # 分区目录相对路径，'' 表示根
        self.mirror = None        # 镜像成员名，如 system/.so
        self.vblock = None
        self.idx_dirs = []        # ['system/00000000', ...] 分片
        self.has = set()          # 该分区的全部成员名
        self.mod_dir = None
        self.plan = None
        self.done = False
        self.mirror_size = 0

    @property
    def name(self):
        return self.rel.rsplit('/', 1)[-1] if self.rel else '(根)'

    def owns(self, member):
        return member in self.has

    def is_core(self, member):
        if member in (self.mirror, self.vblock):
            return True
        for d in self.idx_dirs:
            if member.startswith(d + '/'):
                return True
        return False


def probe(src):
    """按「索引目录」反推分区：<part>/<8hex>/<文件> 的父目录就是分区根。

    这样不必把几千个成员挨个读头，只有分区根下的候选文件才读 4 字节确认 SOMV。
    """
    members = src.members()
    by_dir = {}
    for name, size in members:
        parent = name.rsplit('/', 1)[0] if '/' in name else ''
        by_dir.setdefault(parent, []).append((name, size))

    parts = {}
    for parent, items in by_dir.items():
        for name, size in items:
            base = name.rsplit('/', 1)[-1]
            if not is_hex_dir(base):
                continue
            # parent 是 <part>/<8hex>，它的父目录才是分区根
            part_rel = parent.rsplit('/', 1)[0] if '/' in parent else ''
            p = parts.get(part_rel)
            if p is None:
                p = parts[part_rel] = Part(part_rel)
            if parent not in p.idx_dirs:
                p.idx_dirs.append(parent)

    for rel, p in parts.items():
        prefix = (rel + '/') if rel else ''
        direct = [(n, s) for n, s in by_dir.get(rel, [])]
        p.has = {n for n, _ in members if n.startswith(prefix)}
        # 分区根下的直接文件里找 .so，读头 4 字节确认 SOMV
        cands = [(n, s) for n, s in direct
                 if n.rsplit('/', 1)[-1].lower().endswith('.so')]
        for n, s in cands:
            if src.head(n, 8)[:4] == vp.MAGIC:
                p.mirror, p.mirror_size = n, s
                break
        if not p.mirror:
            # 名字不限 .so 的兜底：逐个读头（分区根下文件通常不多）
            for n, s in direct:
                if s < 64:
                    continue
                if src.head(n, 8)[:4] == vp.MAGIC:
                    p.mirror, p.mirror_size = n, s
                    break
        for n, s in direct:
            if n.rsplit('/', 1)[-1] == 'vblock':
                p.vblock = n
        p.idx_dirs.sort()
    return [p for p in parts.values() if p.mirror]


def match_mod_dir(part, mods_root, maps):
    """找到这个分区对应的「改过的目录」

    顺序很重要：vmos_auto 解包出来是扁平的（vmos_out/system、vmos_out/vendor），
    而原包里可能是嵌套的（root/system/.so、root/vendor/.so）。
    先按分区名找，再按原包相对路径找 —— 反过来会把 root 分区里那个叫 vendor
    的明文目录当成 vendor 分区，条目数从 145 掉到 34，静默丢一大半文件。
    """
    if part.name in maps:
        return maps[part.name]
    if part.rel and maps.get(part.rel):
        return maps[part.rel]
    if not mods_root:
        return None
    by_name = os.path.join(mods_root, part.name)
    if os.path.isdir(by_name) and _looks_like_tree(by_name):
        return by_name
    exact = os.path.join(mods_root, part.rel) if part.rel else mods_root
    if os.path.isdir(exact) and _looks_like_tree(exact):
        return exact
    # 退一步：按名字在解包根里找唯一同名目录
    base = part.name
    hits = []
    for dirpath, dirnames, _ in os.walk(mods_root):
        for d in list(dirnames):
            if d == base:
                full = os.path.join(dirpath, d)
                if _looks_like_tree(full):
                    hits.append(full)
        if dirpath.count(os.sep) - mods_root.count(os.sep) > 3:
            dirnames[:] = []
    if len(hits) == 1:
        return hits[0]
    return None


def _looks_like_tree(d):
    """是不是解出来的明文目录（而不是原包目录：原包目录里有 .so 或索引）"""
    try:
        names = os.listdir(d)
    except OSError:
        return False
    if not names:
        return False
    for n in names:
        p = os.path.join(d, n)
        if os.path.isdir(p) and is_hex_dir(n) and vp.is_old_index(p):
            return False
        if os.path.isfile(p) and n.lower().endswith('.so'):
            try:
                with open(p, 'rb') as f:
                    if f.read(4) == vp.MAGIC:
                        return False
            except OSError:
                pass
    return True


# ────────────────────────────── 镜像流式写出 ──────────────────────────────
def plan_layout(root, count, mtime_override=None, inherit=None):
    """算 inode 表与数据区布局（与 vmos_pack.build_image 完全同规则）"""
    nodes = [root] + vp.flatten(root)
    nodes.sort(key=lambda x: x.ino)

    data_start = max(vp.MIN_DATA, vp.align(vp.HEAD + vp.REC * count))
    pos = data_start
    files = []
    for n in nodes:
        if mtime_override is not None:
            n.mtime = mtime_override
        if inherit:
            s = inherit.get(n.path)
            if s:
                if not n.uid and not n.gid:
                    n.uid, n.gid = s['uid'], s['gid']
                if mtime_override is None and s['mtime']:
                    n.mtime = s['mtime']
                om = s.get('mode') or 0
                if (om & 0o111) and not (n.mode & 0o111):
                    n.mode = (n.mode & ~0o777) | (om & 0o777)
        if n.is_dir:
            n.offset = 0
            continue
        n.offset = vp.align(pos)
        files.append(n)
        pos = n.offset + n.size()

    end = vp.align(pos)
    return data_start, files, end


def make_header(root, count, data_size):
    if data_size > 0xFFFFFFFF:
        raise SystemExit(
            f'镜像数据区 {human(data_size)}，超过 SOMV 头里的 4 GB 上限\n'
            f'  最常见的原因：分区目录里混进了上一次打包的 .so（镜像套镜像）\n'
            f'  检查目录里是否有 .so / vblock / 8 位 hex 索引目录，'
            f'删掉它们再试')
    head = bytearray(vp.HEAD)
    head[0:4] = vp.MAGIC
    struct.pack_into('<III', head, 4, vp.VER, count, data_size)
    recs = bytearray(vp.REC * count)
    for n in [root] + vp.flatten(root):
        o = vp.REC * n.ino
        size = 0 if n.is_dir else n.size()
        nlink = 2 if n.is_dir else 1
        struct.pack_into('<H', recs, o + 0, n.mode & 0xFFFF)
        struct.pack_into('<H', recs, o + 2, 0)
        struct.pack_into('<HH', recs, o + 4, n.uid & 0xFFFF, n.gid & 0xFFFF)
        struct.pack_into('<I', recs, o + 8, 0)
        struct.pack_into('<I', recs, o + 12, nlink)
        struct.pack_into('<III', recs, o + 16, n.mtime, n.mtime, n.mtime)
        struct.pack_into('<I', recs, o + 28, size)
        struct.pack_into('<I', recs, o + 32, n.offset)
        struct.pack_into('<I', recs, o + 36, 0)
        struct.pack_into('<I', recs, o + 40, 0)
    return bytes(head), bytes(recs)


def emit_image(root, count, sink, mtime_override=None, inherit=None,
               progress=None, layout=None):
    """顺序写出整张镜像，内存恒定，可直接写进 zip 流。

    与 vmos_pack.build_image 的唯一区别：那边用 seek 跳空洞，
    这边用一个 write 流，所以空洞要显式补 0 —— 字节内容完全相同。
    传入 layout 可复用已算好的布局，避免重复扫描。
    """
    if layout is None:
        layout = plan_layout(root, count, mtime_override, inherit)
    data_start, files, end = layout
    data_size = end - data_start
    head, recs = make_header(root, count, data_size)

    sink.write(head)
    sink.write(recs)
    cur = vp.HEAD + vp.REC * count
    if cur < data_start:
        sink.write(b'\0' * (data_start - cur))
        cur = data_start

    total = end - cur
    done = 0
    last = 0.0
    for n in files:
        if n.offset > cur:
            pad = n.offset - cur
            sink.write(b'\0' * pad)
            cur = n.offset
            done += pad
        for b in n.chunks():
            sink.write(b)
        written = n.size()
        cur += written
        done += written
        if progress and total:
            now = time.time()
            if now - last > 1.0:
                last = now
                progress(min(1.0, done / total))
    if cur < end:
        sink.write(b'\0' * (end - cur))
    if progress:
        progress(1.0)
    return data_size, len(files), end


# ────────────────────────────── 单个分区 ──────────────────────────────
def read_index_ents(src, part):
    """从源里读该分区的索引，返回 {inode: [(名字, 子inode)]}"""
    merged = {}
    for d in part.idx_dirs:
        prefix = d + '/'
        for name, size in src.members():
            if not name.startswith(prefix):
                continue
            fn = name[len(prefix):]
            if '/' in fn:
                continue
            try:
                ino = int(fn, 16)
            except ValueError:
                continue
            slot = merged.setdefault(ino, {})
            try:
                with src.open(name) as f:
                    raw = f.read()
            except OSError:
                continue
            for line in raw.decode('utf-8', 'replace').splitlines():
                if '=' in line:
                    a, b = line.rsplit('=', 1)
                    try:
                        slot[a] = int(b, 16)
                    except ValueError:
                        pass
    return {k: list(v.items()) for k, v in merged.items()}


def load_inherit_any(src, part):
    """无论源是目录还是 zip，都读出 path -> {uid,gid,mtime,ino,mode}

    目录源直接复用 vmos_pack.load_inherit；zip 源只读 inode 表（几百 KB），
    不必把几 GB 的镜像解出来 —— 否则 system 一解就是 2.6 GB 临时空间。
    """
    if src.kind == 'dir':
        d = os.path.join(src.root, part.rel) if part.rel else src.root
        return vp.load_inherit(d) if os.path.isdir(d) else None

    ents = read_index_ents(src, part)
    if not ents:
        return None
    with src.open(part.mirror) as f:
        hdr = f.read(vp.HEAD)
        if hdr[:4] != vp.MAGIC:
            return None
        _, count, _ = struct.unpack_from('<III', hdr, 4)
        table = f.read(vp.REC * count)

    def rec_at(ino):
        o = vp.REC * ino
        if ino < 0 or o + vp.REC > len(table):
            return None
        return table[o:o + vp.REC]

    meta = {}
    b0 = rec_at(0)
    if b0:
        uid, gid = struct.unpack_from('<HH', b0, 4)
        mt, = struct.unpack_from('<I', b0, 24)
        mode, = struct.unpack_from('<H', b0, 0)
        meta[''] = {'uid': uid, 'gid': gid, 'mtime': mt, 'ino': 0, 'mode': mode}

    def walk(ino, pre):
        for name, child in ents.get(ino, []):
            p = pre + '/' + name
            b = rec_at(child)
            if b:
                uid, gid = struct.unpack_from('<HH', b, 4)
                mt, = struct.unpack_from('<I', b, 24)
                mode, = struct.unpack_from('<H', b, 0)
                meta[p] = {'uid': uid, 'gid': gid, 'mtime': mt, 'ino': child,
                           'mode': mode}
            if child in ents:
                walk(child, p)
    walk(0, '')
    return meta


def build_part(part, src, workdir, args):
    """扫描改过的目录 → 补齐镜像独有文件 → 分配 inode → 得出布局"""
    mod_dir = part.mod_dir

    links = vp.load_links(mod_dir)
    # 解包器留下的辅助文件不能进镜像：清单、目录树、中间 zip、_recovered/
    skip = set()
    try:
        for fn in os.listdir(mod_dir):
            if (fn in ('_links.tsv', '_recovered')
                    or fn.endswith(('_tree.txt', '_manifest.txt', '_unpacked.zip'))):
                skip.add(os.path.join(mod_dir, fn))
    except OSError:
        pass

    # 目录本身就是「打包产物」（含 .so / vblock / 索引目录）时，这些是上一次
    # 打包留下的成品，不能再当明文打进去 —— 否则新镜像里会嵌一个自己，
    # 体积直接翻倍，2 GB 的 system 会撞上 SOMV 的 u32 上限。
    # 真正的分区内容由后面的 merge_image_tree 从镜像里补回来。
    for fn, magic in (('.so', vp.MAGIC), ('vblock', b'KLBV')):
        p = os.path.join(mod_dir, fn)
        if os.path.isfile(p) and not os.path.islink(p):
            try:
                with open(p, 'rb') as f:
                    if f.read(4) == magic:
                        skip.add(p)
            except OSError:
                pass
    try:
        for fn in os.listdir(mod_dir):
            if is_hex_dir(fn):
                p = os.path.join(mod_dir, fn)
                if os.path.isdir(p) and not os.path.islink(p):
                    skip.add(p)
    except OSError:
        pass

    # _recovered/ 不进镜像（里面是名字丢失的兜底文件），但不能悄悄丢：
    # 索引覆盖不到 100% 的包，重打后会少掉这一批 inode，镜像头 count 也跟着缩水。
    rec_dir = os.path.join(mod_dir, '_recovered')
    if os.path.isdir(rec_dir):
        try:
            n_rec = len([x for x in os.listdir(rec_dir)
                         if os.path.isfile(os.path.join(rec_dir, x))])
        except OSError:
            n_rec = 0
        if n_rec:
            print(f'  ⚠ _recovered/ 里 {n_rec} 个条目不会进镜像'
                  f'（它们是索引里没有的 inode，名字已丢失，无法写回目录树）')
            print(f'     要保留：用 vmos_inode_pack.py 按 inode 回填，别走整包重建；'
                  f'或先确认原包索引是 100% 覆盖')

    root, skipped = vp.scan(mod_dir, skip, links)

    # 改过的目录里若还有镜像/索引（直接指向原包目录），先把镜像独有文件补回来
    if vp.find_image(mod_dir):
        added, _ = vp.merge_image_tree(root, mod_dir, workdir)
        if added:
            print(f'  从镜像补回 {added} 个仅存在于镜像中的条目')

    inherit = load_inherit_any(src, part)
    if inherit:
        print(f'  继承元数据 {len(inherit)} 条（uid/gid/mtime/mode 全按原包）')
    ntree = len(vp.flatten(root))
    want = len(inherit) - 1 if inherit else 0
    if inherit and ntree < want:
        ratio = ntree / want if want else 1.0
        msg = f'目录里只有 {ntree} 个条目，镜像里有 {want} 个（{ratio:.0%}）'
        if ratio < 0.5 and not getattr(args, 'force', False):
            raise SystemExit(
                f'\n{part.name}: {msg}\n'
                f'  这不是正常改动，多半是分区目录配错了。\n'
                f'  现在用的是: {mod_dir}\n'
                f'  用 --map {part.name}=正确的分区目录 指定，'
                f'或加 --force 强行继续。')
        print(f'  ⚠ {msg}，可能有缺失')

    keep = None
    if inherit and args.keep_inode:
        keep = {k: v['ino'] for k, v in inherit.items()}
    count = vp.assign_inodes(root, keep)
    nodes = vp.flatten(root)
    nfile = sum(1 for n in nodes if not n.is_dir)
    nlink = sum(1 for n in nodes if n.is_link)
    return root, count, inherit, nfile, nlink, skipped


def write_part(zf, part, mod_root, count, inherit, args):
    """把 .so / vblock / 索引写进 zip（顺序在首次遇到该分区成员处）"""
    prefix = (part.rel + '/') if part.rel else ''
    comp = zipfile.ZIP_STORED if args.store else zipfile.ZIP_DEFLATED

    # 1. 镜像：先算布局（只 stat，不读内容），再按布局流式写
    layout = plan_layout(mod_root, count, args.mtime, inherit)
    end = layout[2]
    bar = ShowProgress(f'  {part.name} 镜像')
    zi = zipfile.ZipInfo(part.mirror, time.localtime()[:6])
    zi.compress_type = comp
    zi.external_attr = 0o644 << 16
    with zf.open(zi, 'w', force_zip64=end > ZIP64_LIMIT) as dst:
        data_size, nfile, _ = emit_image(mod_root, count, dst,
                                         progress=bar.step, layout=layout)
    bar.done(human(end))

    # 2. vblock
    zi = zipfile.ZipInfo(prefix + 'vblock', time.localtime()[:6])
    zi.compress_type = comp
    zi.external_attr = 0o644 << 16
    with zf.open(zi, 'w', force_zip64=False) as dst:
        dst.write(vp.build_vblock(count))

    # 3. 索引（写临时目录再逐个塞进 zip）
    idir = os.path.join(args._tmp, f'idx_{part.name}')
    shutil.rmtree(idir, ignore_errors=True)
    vp.write_index(mod_root, idir)
    idx_list = vp.index_files(idir)
    for sub, fn in idx_list:
        p = os.path.join(idir, sub, fn)
        size = os.path.getsize(p)
        zi = zipfile.ZipInfo(f'{prefix}{sub}/{fn}', time.localtime()[:6])
        zi.compress_type = comp
        zi.external_attr = 0o644 << 16
        with zf.open(zi, 'w', force_zip64=False) as dst, open(p, 'rb') as f:
            while True:
                b = f.read(COPY_CHUNK)
                if not b:
                    break
                dst.write(b)
    return count, nfile, data_size, end, len(idx_list)


class ShowProgress:
    """一行刷新的进度，终端里看得见，管道里退化成 10% 一个点"""

    def __init__(self, label):
        self.label = label
        self.tty = sys.stdout.isatty()
        self.last = -1

    def step(self, p):
        pct = int(p * 100)
        if pct // 10 == self.last:
            return
        self.last = pct // 10
        if self.tty:
            sys.stdout.write(f'\r{self.label} {pct:3d}%')
            sys.stdout.flush()
        else:
            sys.stdout.write('.')
            sys.stdout.flush()

    def done(self, note=''):
        if self.tty:
            sys.stdout.write(f'\r{self.label} 100%  {note}\n')
        else:
            sys.stdout.write(f'  {note}\n')
        sys.stdout.flush()


# ────────────────────────────── 主流程 ──────────────────────────────
def seven_zip_size(path):
    """7z 解压后总大小（只读清单，不真解）"""
    exe = shutil.which('7z') or shutil.which('7za') or shutil.which('7zr')
    if not exe:
        return None
    try:
        out = subprocess.run([exe, 'l', '-slt', path], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=120).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    total = 0
    for line in out.decode('utf-8', 'replace').splitlines():
        if line.startswith('Size = '):
            try:
                total += int(line[7:])
            except ValueError:
                pass
    return total or None


def check_space(src_path, workdir, force):
    """7z 要先解出来，输出还要再写一份，提前把话说清楚"""
    need = os.path.getsize(src_path)
    if src_path.lower().endswith('.7z'):
        n = seven_zip_size(src_path)
        if n:
            need = n * 2            # 解压一份 + 输出一份
    target = workdir or tempfile.gettempdir()
    try:
        free = shutil.disk_usage(target).free
    except OSError:
        return
    print(f'预计需要约 {human(need)} 空间，{target} 可用 {human(free)}')
    if need > free:
        msg = (f'空间可能不够：需要约 {human(need)}，可用 {human(free)}\n'
               f'  用 --workdir 指到空间更大的盘，或先手动解包再传目录')
        if not force:
            raise SystemExit(msg)
        print('⚠ ' + msg)


def main():
    ap = argparse.ArgumentParser(
        description='把改过的分区重打包回整个 ROM 大包（zip/7z/目录）',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''示例:
  python3 vmos_rom.py android15_user_20008.7z out/ -o rom_new.7z
  python3 vmos_rom.py rom.7z out/ --only system,vendor -o rom_new.7z
  python3 vmos_rom.py rom.7z out/ --map system=/data/work/sys -o new.7z
  python3 vmos_rom.py rom.7z out/ -o new.7z --7z-level 5
  python3 vmos_rom.py rom.7z out/ -o new.zip --store
  python3 vmos_rom.py rom.7z out/ --list
''')
    ap.add_argument('src', help='原大包（.7z/.zip）或已解开的目录')
    ap.add_argument('mods', nargs='?', help='vmos_auto.py 解包出来的根目录')
    ap.add_argument('-o', '--out', help='输出包（默认 <原包名>_repack.zip）')
    ap.add_argument('--map', action='append', default=[], metavar='名字=路径',
                    help='手动指定某分区的新目录，可多次')
    ap.add_argument('--only', help='只重建这些分区（逗号分隔），其余原样保留')
    ap.add_argument('--skip', default='', help='跳过这些分区（逗号分隔）')
    ap.add_argument('--level', type=int, default=6, help='zip 压缩级别 0-9，默认 6')
    ap.add_argument('--store', action='store_true', help='zip 不压缩（最快）')
    ap.add_argument('--7z-level', dest='level7z', type=int, default=0,
                    help='7z 压缩级别 0-9，默认 0（只存储：最快，且能随机读，'
                         '和原包一致）')
    ap.add_argument('--7z-solid', dest='seven_solid', action='store_true',
                    help='7z 用固实压缩（更小，但读一个文件也要解整包，'
                         'VMOS 启动会变慢）')
    ap.add_argument('--mtime', type=int, help='统一时间戳（秒）')
    ap.add_argument('--no-keep-inode', dest='keep_inode', action='store_false',
                    help='不沿用原 inode 号（默认沿用）')
    ap.add_argument('--no-sync-plain', dest='sync_plain', action='store_false',
                    help='不更新包里原有的明文副本（默认会同步，避免包里新旧不一致）')
    ap.add_argument('--list', action='store_true', help='只列识别结果，不写包')
    ap.add_argument('--workdir', help='临时目录（7z 解压用，默认系统临时目录）')
    ap.add_argument('--keep-temp', action='store_true')
    ap.add_argument('--no-verify', action='store_true', help='跳过结构校验')
    ap.add_argument('--force', action='store_true', help='空间不足时仍然继续')
    ap.add_argument('--version', action='version', version=f'vmos_rom {VERSION}  ({BUILD_NOTE})')
    args = ap.parse_args()

    src_path = os.path.abspath(args.src)
    if not os.path.exists(src_path):
        raise SystemExit('找不到: ' + src_path)

    maps = {}
    for kv in args.map:
        if '=' not in kv:
            raise SystemExit(f'--map 需要 名字=路径 形式: {kv}')
        k, v = kv.split('=', 1)
        maps[k.strip()] = os.path.abspath(v.strip())

    workdir = os.path.abspath(args.workdir) if args.workdir else None
    if workdir:
        os.makedirs(workdir, exist_ok=True)
    if not os.path.isdir(src_path):
        check_space(src_path, workdir, args.force)
    args._tmp = tempfile.mkdtemp(prefix='romrepack_', dir=workdir)

    src = None
    extracted = None
    staging = None
    staging_own = False
    try:
        src, extracted = open_source(src_path, workdir)
        print(f'源: {src_path}  ({src.kind})')

        parts = probe(src)
        if not parts:
            raise SystemExit('没在这个包里找到 SOMV 分区。'
                             '先用 vmos_auto.py --probe 看看。')

        only = {s.strip() for s in args.only.split(',') if s.strip()} if args.only else None
        skip = {s.strip() for s in args.skip.split(',') if s.strip()}

        print(f'\n识别到 {len(parts)} 个分区:')
        todo = []
        for p in parts:
            p.mod_dir = match_mod_dir(p, args.mods and os.path.abspath(args.mods), maps)
            mark = ''
            if only and p.name not in only and p.rel not in only:
                mark = '  → 保持原样（--only）'
            elif p.name in skip:
                mark = '  → 保持原样（--skip）'
            elif not p.mod_dir:
                mark = '  → 找不到改过的目录，保持原样'
            else:
                mark = f'  → 重建自 {p.mod_dir}'
            print(f'  {p.name:<16} 镜像 {p.mirror:<28} '
                  f'{human(p.mirror_size):>10}  索引 {len(p.idx_dirs)} 片{mark}')
            if not mark.startswith('  → 保持') and not mark.startswith('  → 找不到'):
                todo.append(p)

        if args.list:
            print('\n--list：只诊断，不写包')
            return
        if not todo:
            raise SystemExit('\n没有要重建的分区。检查 --map 或 mods 目录是否给对。')

        src_ext = os.path.splitext(src_path)[1].lower()
        default_ext = ('.7z' if src_ext in ('.7z', '.xz', '.tar', '.tgz',
                                            '.bz2', '.gz') else '.zip')
        out = args.out or (os.path.splitext(src_path)[0] + '_repack'
                           + default_ext)
        out = os.path.abspath(out)
        ext = os.path.splitext(out)[1].lower()
        if ext not in ('.7z', '.zip'):
            raise SystemExit(f'输出只支持 .7z 或 .zip，你给的是 '
                             f'{ext or "无扩展名"}\n'
                             f'  例如: -o rom_new.7z')
        fmt7z = ext == '.7z'
        if fmt7z:
            seven_zip_exe()        # 提前确认，别等解包完才发现没有 7z
        if out == src_path:
            raise SystemExit('输出路径和输入是同一个文件，换个名字')
        os.makedirs(os.path.dirname(out) or '.', exist_ok=True)
        if os.path.exists(out):
            os.remove(out)

        comp = zipfile.ZIP_STORED if args.store else zipfile.ZIP_DEFLATED
        level = None if args.store else max(0, min(9, args.level))

        print(f'\n构建 {len(todo)} 个分区 → {out}')
        plans = {}
        for p in todo:
            print(f'\n[{p.name}]')
            root, count, inherit, nfile, nlink, skipped = build_part(
                p, src, args._tmp, args)
            plans[p.name] = (root, count, inherit)
            print(f'  inode {count}（目录 {count - nfile} / 文件 {nfile}'
                  f'，链接 {nlink}）')
            if skipped:
                print(f'  跳过 {len(skipped)} 项（_links.tsv 等）')

        total_in = 0
        total_out = 0
        expect = {}

        if fmt7z:
            staging, staging_own = make_staging(src, extracted, workdir)
            print('\n写出:')
            t0 = time.time()
            for p in todo:
                root, count, inherit = plans[p.name]
                nfile, ds, end, nidx = write_part_dir(
                    staging, p, root, count, inherit, args)
                expect[p.mirror] = (end, count, nidx)
                total_out += end
                p.done = True
            if args.sync_plain:
                n = sync_plain_dir(staging, todo)
                if n:
                    print(f'\n同步明文副本 {n} 个')
            pack_7z(out, staging, args)
        else:
            print('\n写出:')
            t0 = time.time()
            with zipfile.ZipFile(out, 'w', comp, compresslevel=level,
                                 allowZip64=True) as zf:
                pending = {p.name: p for p in todo}
                for name, size in src.members():
                    owner = None
                    for p in todo:
                        if name in p.has:
                            owner = p
                            break
                    if owner is not None and not owner.done:
                        root, count, inherit = plans[owner.name]
                        c, nf, ds, end, nidx = write_part(
                            zf, owner, root, count, inherit, args)
                        owner.done = True
                        pending.pop(owner.name, None)
                        total_out += end
                    if owner is not None and owner.is_core(name):
                        continue
                    # 其余成员原样流式拷贝（--sync-plain 时用改过的明文覆盖）
                    override = None
                    if args.sync_plain and owner is not None and owner.mod_dir:
                        rel = name[len(owner.rel) + 1:] if owner.rel else name
                        cand = os.path.join(owner.mod_dir,
                                            rel.replace('/', os.sep))
                        if os.path.isfile(cand) and not os.path.islink(cand):
                            override = cand
                    if override:
                        copy_into(zf, name, os.path.getsize(override), comp,
                                  lambda p=override: open(p, 'rb'))
                    else:
                        copy_into(zf, name, size, comp,
                                  lambda n=name: src.open(n))
                    total_in += size

                # 分区成员在原包里一条都没有的情况（少见）
                for p in list(pending.values()):
                    root, count, inherit = plans[p.name]
                    write_part(zf, p, root, count, inherit, args)
                    p.done = True

        detail = (f'重建镜像 {human(total_out)}，'
                  f'用时 {time.time() - t0:.0f}s')
        if not fmt7z:
            detail = f'拷贝原有 {human(total_in)}，' + detail
        print(f'\n输出 {out}  ({human(os.path.getsize(out))}，{detail})')
        print(f'\n把 {os.path.basename(out)} 改名替换原包即可。')
        # 6 个启动侧车的 size/sha256 登记在 boot-sidecars.json 里，改了文件就要同步，
        # 否则宿主 flat overlay 会失败（[APEX-APP] flat overlay failed → abort boot）
        print('  若改过 vendor/lib64/egl、gralloc 或 system/lib64 那两个 vmos stub，')
        print('  记得同步登记表：vmos_sidecar_fix.py ' + os.path.basename(out) +
              ' --mods <解包目录> -o ' + os.path.basename(out))

        if not args.no_verify:
            if fmt7z:
                check_7z(out, expect)
            else:
                quick_check(out, plans)
    finally:
        if src:
            src.close()
        if not args.keep_temp:
            if extracted:
                shutil.rmtree(extracted, ignore_errors=True)
            if staging_own and staging:
                shutil.rmtree(staging, ignore_errors=True)
            shutil.rmtree(args._tmp, ignore_errors=True)


# ────────────────────────────── 7z 输出 ──────────────────────────────
def seven_zip_exe():
    exe = shutil.which('7z') or shutil.which('7za') or shutil.which('7zr')
    if not exe:
        raise SystemExit('要输出 .7z 需要 7z 命令\n'
                         '  Termux: pkg install p7zip\n'
                         '  Debian/Ubuntu: apt install p7zip-full\n'
                         '  或者改成输出 zip：-o xxx.zip')
    return exe


def clone_tree(src_root, dest):
    """把目录拷成一份可以随便改的副本；优先硬链接，几乎不占空间"""
    n = 0
    for dp, dns, fns in os.walk(src_root):
        rel = os.path.relpath(dp, src_root)
        tgt = dest if rel == '.' else os.path.join(dest, rel)
        os.makedirs(tgt, exist_ok=True)
        for fn in fns + dns:
            s = os.path.join(dp, fn)
            d = os.path.join(tgt, fn)
            if os.path.islink(s):
                if not os.path.lexists(d):
                    try:
                        os.symlink(os.readlink(s), d)
                    except OSError:
                        pass
                continue
            if os.path.isdir(s):
                continue
            try:
                os.link(s, d)
            except OSError:
                try:
                    shutil.copy2(s, d)
                except OSError:
                    pass
            n += 1
    return n


def unzip_into(src, dest):
    """把 zip 按成员解到 dest，路径穿越的一律跳过"""
    with zipfile.ZipFile(src.path) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        total = sum(i.file_size for i in infos)
        print(f'解压 zip → {dest}（{human(total)}）')
        t0 = time.time()
        for info in infos:
            rel = info.filename.replace('\\', '/').lstrip('/')
            p = os.path.normpath(os.path.join(dest, rel.replace('/', os.sep)))
            if p != dest and not p.startswith(dest + os.sep):
                continue
            d = os.path.dirname(p)
            if d:
                os.makedirs(d, exist_ok=True)
            if os.path.islink(p):
                os.unlink(p)
            with zf.open(info) as s, open(p, 'wb') as f:
                while True:
                    b = s.read(COPY_CHUNK)
                    if not b:
                        break
                    f.write(b)
        print(f'  完成，用时 {time.time() - t0:.0f}s')
    return len(infos)


def make_staging(src, extracted, workdir):
    """准备一个可以随便改的目录树，7z 就从这里整体打包"""
    if extracted:
        return extracted, False          # 7z 源已经解在这里了，直接用
    dest = tempfile.mkdtemp(prefix='romstage_', dir=workdir)
    if src.kind == 'zip':
        unzip_into(src, dest)
    else:
        print(f'复制源目录 → {dest}（硬链接，不占空间）')
        clone_tree(src.root, dest)
    return dest, True


def write_part_dir(root_dir, part, mod_root, count, inherit, args):
    """把 .so / vblock / 索引落到暂存目录（7z 输出用，写法与写 zip 等价）"""
    base = (os.path.join(root_dir, part.rel.replace('/', os.sep))
            if part.rel else root_dir)
    os.makedirs(base, exist_ok=True)

    layout = plan_layout(mod_root, count, args.mtime, inherit)
    end = layout[2]
    bar = ShowProgress(f'  {part.name} 镜像')
    dst_path = os.path.join(base, '.so')
    tmp = dst_path + '.vmostmp'
    with open(tmp, 'wb') as f:
        data_size, nfile, _ = emit_image(mod_root, count, f,
                                         progress=bar.step, layout=layout)
    if os.path.islink(dst_path):
        os.unlink(dst_path)
    os.replace(tmp, dst_path)
    bar.done(human(end))

    p = os.path.join(base, 'vblock')
    t = p + '.vmostmp'
    with open(t, 'wb') as f:
        f.write(vp.build_vblock(count))
    if os.path.islink(p):
        os.unlink(p)
    os.replace(t, p)

    # 旧索引分片整体清掉（含新布局不再使用的分片名），再按 inode 高位重写
    for q in {os.path.join(root_dir, d.replace('/', os.sep)) for d in part.idx_dirs}:
        if os.path.islink(q):
            os.unlink(q)
        elif os.path.isdir(q):
            shutil.rmtree(q, ignore_errors=True)
    for sub in os.listdir(base):
        sp = os.path.join(base, sub)
        if not IDX_RE.match(sub):
            continue
        if os.path.islink(sp):
            os.unlink(sp)
        elif os.path.isdir(sp):
            shutil.rmtree(sp, ignore_errors=True)
    vp.write_index(mod_root, base)
    return nfile, data_size, end, len(vp.index_files(base))


def sync_plain_dir(staging, todo):
    """用改过的明文覆盖暂存目录里同名的旧副本（只覆盖原有的，不新增）"""
    n = 0
    aux = ('_links.tsv',)
    for part in todo:
        if not part.mod_dir:
            continue
        base = (os.path.join(staging, part.rel.replace('/', os.sep))
                if part.rel else staging)
        for dp, dns, fns in os.walk(part.mod_dir):
            rel = os.path.relpath(dp, part.mod_dir)
            for fn in fns:
                if fn in aux or fn.endswith(('_tree.txt', '_manifest.txt',
                                             '_unpacked.zip')):
                    continue
                s = os.path.join(dp, fn)
                if os.path.islink(s) or not os.path.isfile(s):
                    continue
                r = fn if rel == '.' else os.path.join(rel, fn)
                d = os.path.join(base, r)
                if os.path.islink(d) or not os.path.isfile(d):
                    continue          # 原包里没有这个明文，不铺
                t = d + '.vmostmp'
                shutil.copyfile(s, t)
                os.replace(t, d)
                n += 1
    return n


def pack_7z(out, staging, args):
    """调 7z 把暂存目录整体打成 7z"""
    exe = seven_zip_exe()
    items = sorted(x for x in os.listdir(staging) if not x.endswith('.vmostmp'))
    if not items:
        raise SystemExit('暂存目录是空的，没法打包')
    lv = max(0, min(9, args.level7z))
    cmd = [exe, 'a', '-t7z', f'-mx={lv}', '-y', '-bso0', '-bsp0']
    if not args.seven_solid:
        cmd.append('-ms=off')          # 非固实：单个文件可独立解压
    if os.path.exists(out):
        os.remove(out)
    cmd += [out] + items
    mode = '固实' if args.seven_solid else '非固实'
    print(f'\n7z 打包 {len(items)} 个顶层项，级别 {lv}（{mode}）…')
    t0 = time.time()
    r = subprocess.run(cmd, cwd=staging, stdout=subprocess.DEVNULL,
                       stderr=subprocess.PIPE)
    if r.returncode != 0:
        msg = r.stderr.decode('utf-8', 'replace').strip()
        raise SystemExit(f'7z 打包失败（{r.returncode}）: {msg[:400]}')
    return time.time() - t0


def check_7z(out, expect):
    """用 7z l 读回成员大小，逐个核对该分区镜像"""
    exe = seven_zip_exe()
    print('\n结构校验:')
    r = subprocess.run([exe, 'l', '-slt', out], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
    if r.returncode != 0:
        print('  ✗ 输出包读不了')
        return False
    size, cur = {}, None
    for line in r.stdout.decode('utf-8', 'replace').splitlines():
        if line.startswith('Path = '):
            cur = line[7:]
        elif line.startswith('Size = ') and cur:
            try:
                size[cur] = int(line[7:])
            except ValueError:
                pass
            cur = None
    ok = True
    for mirror, (end, count, nidx) in expect.items():
        got = size.get(mirror)
        if got is None:
            print(f'  ✗ 缺少 {mirror}')
            ok = False
            continue
        mark = '✓' if got == end else '✗'
        print(f'  {mark} {mirror:<26} {human(got):>10}  inode {count:<6} '
              f'索引文件 {nidx} 个')
        ok = ok and got == end
    print('  ✓ 结构完整' if ok else '  ✗ 有问题，把上面的输出发我')
    return ok


def copy_into(zf, name, size, comp, opener):
    """把一个成员流式写进 zip，内存恒定"""
    zi = zipfile.ZipInfo(name, time.localtime()[:6])
    zi.compress_type = comp
    zi.external_attr = 0o644 << 16
    with zf.open(zi, 'w', force_zip64=size > ZIP64_LIMIT) as dst:
        with opener() as f:
            while True:
                b = f.read(COPY_CHUNK)
                if not b:
                    break
                dst.write(b)


def quick_check(out, plans):
    """结构校验：重新打开 zip，读每个镜像的头与 inode 表，核对条数"""
    print('\n结构校验:')
    ok = True
    with zipfile.ZipFile(out) as zf:
        names = set(zf.namelist())
        # 有 vblock 的目录就是分区根
        blocks = {n.rsplit('/', 1)[0] for n in names
                  if n.rsplit('/', 1)[-1] == 'vblock'}
        for d in sorted(blocks):
            pref = (d + '/') if d else ''
            so = None
            for n in sorted(names):
                if n.startswith(pref) and n.count('/') == pref.count('/'):
                    with zf.open(n) as f:
                        if f.read(4) == vp.MAGIC:
                            so = n
                            break
            if not so:
                print(f'  ✗ {d or "."} 有 vblock 但找不到 SOMV 镜像')
                ok = False
                continue
            with zf.open(so) as f:
                hdr = f.read(vp.HEAD)
            _, cnt, dsize = struct.unpack_from('<III', hdr, 4)
            idx = [n for n in names if n.startswith(pref)
                   and is_hex_dir(n[len(pref):].split('/')[0])
                   and n.count('/') > pref.count('/')]
            print(f'  {d or ".":<16} inode {cnt:<6} 数据区 {human(dsize):>10}  '
                  f'索引文件 {len(idx)}')
            ok = ok and cnt > 0
    print('  ✓ 结构完整' if ok else '  ✗ 有问题，请把上面的输出发我')
    return ok


if __name__ == '__main__':
    main()
