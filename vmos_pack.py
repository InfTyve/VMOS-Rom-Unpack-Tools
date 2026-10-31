#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vmos_pack.py —— 把改好的目录 / zip 打包回 VMOS 分区格式
================================================================

    python3 vmos_pack.py vmos_out/vendor              # 产出 vendor/{.so,vblock,00000000/}
    python3 vmos_pack.py 改过的.zip -o repack         # zip 也行
    python3 vmos_pack.py vendor -o repack --zip       # 同时封装成 vendor.zip
    python3 vmos_pack.py vendor --materialize         # 额外铺一份明文文件
    python3 vmos_pack.py vendor --from 原包目录        # 继承原 uid/gid/mtime

生成的结构与原包完全一致，可直接放回 VMOS 使用：

    <out>/<name>/
    ├── .so            SOMV 镜像（头 + inode 表 + 4096 对齐的数据区）
    ├── vblock         KLBV 块表头
    └── 00000000/      目录索引，每个目录一个文件，内容 "名字=inode(hex)\r\n"

格式细节（均已用原包逐字节比对确认）
------------------------------------
  头 64B   "SOMV" | u32 版本=64 | u32 inode 数 | u32 数据区长度   其余全 0
  记录 44B  +0 u16 mode  +2 u16 0  +4 u16 uid  +6 u16 gid  +8 u32 0
            +12 u32 nlink  +16/20/24 atime/ctime/mtime
            +28 u32 size   +32 u32 offset  +36 u32 0  +40 u32 0
  数据区   紧接记录表向上取整到 4096（Roo 90 个 inode → 4096，vendor 146 → 8192）
  nlink    目录恒为 2，普通文件为 1（与原包一致，不按 ext4 规则）
  索引     文件名 = inode 补零 8 位小写 hex；条目 name=hex，按名字字节序，CRLF 换行

inode 分配：0 给根，之后按目录深度优先、同级名字字节序递增 ——
与原包生成器行为一致，因此未改动目录重新打包后可与原镜像逐字节相同。
"""

import argparse
import hashlib
import mmap
import os
import re
import shutil
import struct
import sys
import tempfile
import time
import zipfile

BLOCK = 4096
REC = 44
HEAD = 64
MIN_DATA = 4096
MAGIC = b'SOMV'
VB_MAGIC = b'KLBV'
VER = 64
VERSION = '2026.10.31.1'
BUILD_NOTE = 'mode/uid/gid 以原镜像为准（解包目录权限被改乱也不会写进包）'

S_IFMT, S_IFDIR, S_IFREG, S_IFLNK = 0xF000, 0x4000, 0x8000, 0xA000


# ────────────────────────────── 目录扫描 ──────────────────────────────
LAZY_LIMIT = 4 << 20      # 超过这个大小的文件不预读进内存，构建时流式拷贝
COPY_CHUNK = 1 << 20


class Node:
    __slots__ = ('path', 'name', 'ino', 'mode', 'uid', 'gid', 'mtime',
                 'kind', 'data', 'src', 'target', 'children', 'offset', '_size')

    def __init__(self, path, name):
        self.path = path
        self.name = name
        self.ino = None
        self.mode = 0
        self.uid = 0
        self.gid = 0
        self.mtime = 0
        self.kind = S_IFREG
        self.data = b''
        self.src = None          # 大文件：只记路径，构建/校验时按块读
        self.target = None
        self.children = []
        self.offset = 0
        self._size = 0

    @property
    def is_dir(self):
        return self.kind == S_IFDIR

    @property
    def is_link(self):
        return self.kind == S_IFLNK

    def size(self):
        """文件字节数（不看 data，避免为了取长度把几 GB 读进内存）"""
        if self.src:
            try:
                return os.path.getsize(self.src)
            except OSError:
                return 0
        return len(self.data)

    def chunks(self):
        """按块产出内容，内存占用固定"""
        if self.src:
            with open(self.src, 'rb') as f:
                while True:
                    b = f.read(COPY_CHUNK)
                    if not b:
                        break
                    yield b
        elif self.data:
            yield self.data

    def write_to(self, fp):
        for b in self.chunks():
            fp.write(b)

    def read_all(self, limit=None):
        """小文件用；超过 limit 返回 None（调用方改用 chunks）"""
        if self.src:
            n = self.size()
            if limit is not None and n > limit:
                return None
            with open(self.src, 'rb') as f:
                return f.read()
        return self.data


IDX_NAME_RE = re.compile(r'^[0-9a-f]{1,8}$')


def is_old_index(d):
    """判断目录是不是旧索引（00000000、00000001…），避免把索引当内容打进去。

    索引目录的特征：里面全是 hex 命名的小文件，没有子目录。
    不能只看名字 —— 分片索引有 00000001、00000002 等多个。
    """
    try:
        names = os.listdir(d)
    except OSError:
        return False
    if not names:
        return False
    hex8 = 0
    for n in names:
        p = os.path.join(d, n)
        if os.path.isdir(p) and not os.path.islink(p):
            return False                      # 有子目录，肯定不是索引
        if not IDX_NAME_RE.match(n):
            return False                      # 出现非 hex 名字，不是索引
        if len(n) == 8:
            hex8 += 1
    return hex8 >= max(1, len(names) // 2)


def load_links(pkg_dir):
    """读取解包时生成的 _links.tsv：{相对路径: 目标}"""
    p = os.path.join(pkg_dir, '_links.tsv')
    links = {}
    if not os.path.isfile(p) or os.path.islink(p):
        return links
    try:
        with open(p, encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.rstrip('\r\n')
                if not line or line.startswith('#'):
                    continue
                if '\t' not in line:
                    continue
                rel, tgt = line.split('\t', 1)
                rel = rel.strip().lstrip('/')
                if rel:
                    links['/' + rel] = tgt
    except OSError:
        pass
    return links


def scan(root, skip=(), links=None):
    """把目录读成 Node 树；skip 为需要排除的绝对路径集合"""
    root = os.path.abspath(root)
    rn = Node('', os.path.basename(root))
    rn.kind = S_IFDIR
    st = os.stat(root)
    rn.mode = S_IFDIR | (st.st_mode & 0o7777)
    rn.uid, rn.gid = st.st_uid, st.st_gid
    rn.mtime = int(st.st_mtime)
    skipped = []
    links = links or {}

    def walk(dirpath, parent, rel):
        try:
            entries = os.listdir(dirpath)
        except OSError as e:
            skipped.append((rel or '/', str(e)))
            return
        entries.sort(key=lambda s: s.encode('utf-8', 'surrogateescape'))
        for name in entries:
            full = os.path.join(dirpath, name)
            if full in skip:
                continue
            p = rel + '/' + name
            try:
                st = os.lstat(full)
            except OSError as e:
                skipped.append((p, str(e)))
                continue
            n = Node(p, name)
            if p in links:
                # _links.tsv 里登记的路径一律按链接还原，哪怕磁盘上是占位文本
                n.kind = S_IFLNK
                n.mode = S_IFLNK | 0o777
                n.target = links[p]
                n.data = n.target.encode('utf-8', 'surrogateescape')
                parent.children.append(n)
                continue
            if name in ('_links.tsv',) and rel == '':
                skipped.append((p, '链接清单，不计入镜像'))
                continue
            n.mode = st.st_mode & 0xFFFF
            n.uid, n.gid = st.st_uid, st.st_gid
            n.mtime = int(st.st_mtime)
            fmt = st.st_mode & S_IFMT
            if fmt == S_IFLNK:
                n.kind = S_IFLNK
                try:
                    n.target = os.readlink(full)
                    n.data = n.target.encode('utf-8', 'surrogateescape')
                except OSError:
                    n.target = ''
                    n.data = b''
                parent.children.append(n)
            elif fmt == S_IFDIR:
                # 任何分片索引目录（00000000、00000001…）都跳过，否则会被当成内容打进镜像
                if IDX_NAME_RE.match(name) and is_old_index(full):
                    skipped.append((p, '旧索引目录，已跳过'))
                    continue
                n.kind = S_IFDIR
                parent.children.append(n)
                walk(full, n, p)
            elif fmt in (0, S_IFREG):
                n.kind = S_IFREG
                if st.st_size > LAZY_LIMIT:
                    n.src = full          # 大文件不预读，构建时流式拷贝
                else:
                    try:
                        with open(full, 'rb') as f:
                            n.data = f.read()
                    except OSError as e:
                        skipped.append((p, str(e)))
                        continue
                parent.children.append(n)
            else:
                skipped.append((p, f'特殊文件（{oct(fmt)}），已跳过'))
    walk(root, rn, '')
    return rn, skipped


def assign_inodes(root, keep=None):
    """DFS 前序分配 inode：0 给根，与官方生成器一致。

    keep 为 {相对路径: inode} 时优先沿用原号（路径未变则编号完全复现），
    新增文件追加到最大号之后，删掉的留下空洞（记录全 0）。
    """
    allnodes = [root] + flatten(root)
    if keep:
        used = set()
        for n in allnodes:
            ino = keep.get(n.path)
            if ino is not None and ino not in used:
                n.ino = ino
                used.add(ino)
        nxt = (max(used) + 1) if used else 1
        for n in allnodes:
            if n.ino is None:
                n.ino = nxt
                nxt += 1
        return nxt
    n = 0
    root.ino = n
    n += 1

    def go(node):
        nonlocal n
        for c in node.children:
            c.ino = n
            n += 1
            if c.is_dir:
                go(c)
    go(root)
    return n


def flatten(root):
    out = []

    def go(node):
        for c in node.children:
            out.append(c)
            if c.is_dir:
                go(c)
    go(root)
    return out


# ────────────────────────────── 写镜像 ──────────────────────────────
def align(x, a=BLOCK):
    return (x + a - 1) // a * a


def build_image(root, count, so_path, mtime_override=None, inherit=None,
                meta_from_dir=False):
    """边算边写，内存恒定。

    system 镜像动辄 2.6 GB，旧实现把所有文件读进内存再拼一个 bytearray，
    在手机上必然 OOM。现在只保留元数据，数据按块从源文件拷进目标镜像。
    返回 (数据区长度, 文件数)。
    """
    nodes = [root] + flatten(root)
    nodes.sort(key=lambda x: x.ino)

    data_start = max(MIN_DATA, align(HEAD + REC * count))
    pos = data_start
    files = []
    for n in nodes:
        if mtime_override is not None:
            n.mtime = mtime_override
        if inherit and not meta_from_dir:
            src = inherit.get(n.path)
            if src:
                # uid/gid 一律以原包为准：以普通用户身份重打时目录里的属主
                # 是 1000，不打回来整个 ROM 的属主就全错了
                n.uid, n.gid = src['uid'], src['gid']
                if mtime_override is None and src['mtime']:
                    n.mtime = src['mtime']
                # mode 也以原包为准，但要先看类型位：解包器把符号链接写成
                # 占位文件、或把目录写坏时，类型变了就不能照抄。
                # 以前只补「执行位」，于是 040755→040700、0644→0600 这类
                # 差异会原样进包，改几个文件却能冒出几十条 mode 变化。
                om = src.get('mode') or 0
                if (om & 0o170000) == (n.mode & 0o170000):
                    n.mode = om
                elif (om & 0o111) and not (n.mode & 0o111):
                    n.mode = (n.mode & ~0o777) | (om & 0o777)
            elif not meta_from_dir:
                # 原包里没有的新增文件：属主固定 root，否则普通用户重打会带出 1000
                n.uid = n.gid = 0
        if n.is_dir:
            n.offset = 0
            continue
        n.offset = align(pos)
        files.append(n)
        pos = n.offset + n.size()

    end = align(pos)
    data_size = end - data_start

    head = bytearray(HEAD)
    head[0:4] = MAGIC
    struct.pack_into('<III', head, 4, VER, count, data_size)

    recs = bytearray(REC * count)
    for n in nodes:
        o = REC * n.ino
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

    with open(so_path, 'wb') as f:
        f.write(head)
        f.write(recs)
        cur = HEAD + REC * count
        if cur < data_start:
            f.seek(data_start)
            cur = data_start
        for n in files:
            if n.offset > cur:
                f.seek(n.offset)
                cur = n.offset
            n.write_to(f)
            cur += n.size()
        # 末尾补到 4096 对齐。必须无条件 truncate：
        # 只有根目录、或最后一个文件正好结束在 data_start 时，seek 不会改变文件长度
        f.truncate(end)
    return data_size, len(files)


def build_vblock(count):
    return struct.pack('<4sIII', VB_MAGIC, 16, count, 0)


def idx_shard(ino):
    """索引分片目录名 = (inode >> 12) 的 8 位小写 hex

    依据不是猜的：原包 system 的 00000001/ 里最小索引文件是 00001001，
    也就是 inode 4097 —— 恰好跨过 4096 边界，而 00000000/ 里全是 4096 以下。
    也就是说分片不是「写入批次 / 增量叠加」，而是按 inode 高位分区：
    读取时由 inode 直接算出索引路径（00000001/00001001），
    合并成单个 00000000 会让所有 inode >= 4096 的目录在内核眼里凭空消失。
    """
    return f'{ino >> 12:08x}'


def write_index(root, out_dir):
    """每个目录一个索引文件，内容 name=hex\\r\\n 按名字排序

    落盘路径为 <out_dir>/<ino>>12:08x>/<ino:08x>。out_dir 是分区根，
    分片子目录由 idx_shard 决定，不再固定 00000000。
    """
    os.makedirs(out_dir, exist_ok=True)

    def go(node):
        # 空目录不写索引文件（与原包一致：Roo 31 个目录只有 10 个有索引）
        if node.children:
            d = os.path.join(out_dir, idx_shard(node.ino))
            os.makedirs(d, exist_ok=True)
            lines = [f'{c.name}={c.ino:x}\r\n'
                     for c in sorted(node.children,
                                     key=lambda x: x.name.encode('utf-8', 'surrogateescape'))]
            with open(os.path.join(d, f'{node.ino:08x}'), 'wb') as f:
                f.write(''.join(lines).encode('utf-8', 'surrogateescape'))
        for c in node.children:
            if c.is_dir:
                go(c)
    go(root)


def index_files(out_dir):
    """列出写出的索引文件：[(分片目录名, 文件名), ...]，按分片名排序"""
    out = []
    for sub in sorted(os.listdir(out_dir)):
        sp = os.path.join(out_dir, sub)
        if not (os.path.isdir(sp) and IDX_NAME_RE.match(sub)):
            continue
        for fn in sorted(os.listdir(sp)):
            if IDX_NAME_RE.match(fn):
                out.append((sub, fn))
    return out


LINK_NOTE = ('# 本文件是符号链接占位，不是真实文件\n'
             '# 原链接指向: %s\n'
             '# 未创建真实链接，防止在本机跟随到存储目录。\n'
             '# 打包时会读取 _links.tsv 还原为原链接。\n')


def link_is_safe(base, path, target):
    """相对链接且解析后仍在输出目录内才算安全"""
    if not target or os.path.isabs(target):
        return False
    base = os.path.realpath(base)
    p = os.path.realpath(os.path.join(os.path.dirname(path), target))
    return p == base or p.startswith(base + os.sep)


def materialize(root, dest, link_mode='text'):
    """把文件也明文铺一份（原包里就有这种冗余副本）。

    符号链接默认只写占位文本，理由和解包器一样：ROM 里的 /storage、/system
    这类绝对链接一旦在电脑或手机上变成真链接，删除目录时可能被跟随，
    连本机存储一起删掉。
    """
    links = []
    for n in flatten(root):
        p = os.path.join(dest, n.path.lstrip('/'))
        if n.is_dir:
            os.makedirs(p, exist_ok=True)
            try:
                os.chmod(p, n.mode & 0o7777)
            except OSError:
                pass
        elif n.is_link:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            if os.path.lexists(p):
                os.remove(p)          # 只删链接/文件本身，绝不进入目标
            links.append((n.path, n.target))
            if link_mode == 'raw' or (link_mode == 'safe'
                                      and link_is_safe(dest, p, n.target)):
                try:
                    os.symlink(n.target, p)
                    continue
                except OSError:
                    pass
            with open(p, 'wb') as f:
                f.write((LINK_NOTE % n.target).encode('utf-8'))
        else:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, 'wb') as f:
                n.write_to(f)
            try:
                os.chmod(p, n.mode & 0o7777)
            except OSError:
                pass
    if links and link_mode != 'raw':
        with open(os.path.join(dest, '_links.tsv'), 'w', encoding='utf-8') as f:
            for path, tgt in links:
                f.write(f'{path.lstrip("/")}\t{tgt}\n')


# ────────────────────────────── 读回校验 ──────────────────────────────
def verify(so_path, root):
    """重新解析生成的镜像，逐个比对内容，返回 (ok, bad_list)。

    分块读，2.6 GB 的镜像也不会把内存吃光。
    """
    total = os.path.getsize(so_path)
    with open(so_path, 'rb') as f:
        hdr = f.read(HEAD)
        if hdr[:4] != MAGIC:
            return False, [('镜像魔数错误',)]
        ver, count, dsz = struct.unpack_from('<III', hdr, 4)
        if ver != VER:
            return False, [('版本字段异常', ver)]
        data_start = max(MIN_DATA, align(HEAD + REC * count))
        if total - data_start != dsz:
            return False, [('数据区长度与文件大小不符', dsz, total)]

        recs = {}
        table = f.read(REC * count)
        for i in range(count):
            o = REC * i
            mode, = struct.unpack_from('<H', table, o)
            nlink, = struct.unpack_from('<I', table, o + 12)
            size, = struct.unpack_from('<I', table, o + 28)
            off, = struct.unpack_from('<I', table, o + 32)
            recs[i] = (mode, nlink, size, off)

        bad = []
        nodes = [root] + flatten(root)
        if count < len(nodes):
            bad.append(('inode 数不足', count, len(nodes)))
        buf = bytearray(COPY_CHUNK)
        view = memoryview(buf)
        for n in nodes:
            if n.ino not in recs:
                bad.append(('缺少 inode', n.path, n.ino))
                continue
            mode, nlink, size, off = recs[n.ino]
            if n.kind != S_IFDIR:
                want = n.size()
                if size != want:
                    bad.append(('大小不符', n.path, size, want))
                    continue
                f.seek(off)
                left = size
                same = True
                for chunk in n.chunks():
                    got = f.read(len(chunk))
                    if got != chunk:
                        same = False
                        break
                    left -= len(chunk)
                if same and left != 0:
                    same = False
                if not same:
                    bad.append(('内容不符', n.path))
            else:
                if size != 0 or off != 0:
                    bad.append(('目录字段异常', n.path, size, off))
    return not bad, bad


# ────────────────────────────── 输入 ──────────────────────────────
def extract_zip(zip_path, dest):
    dest = os.path.abspath(dest)
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            name = info.filename
            if not info.flag_bits & 0x800:
                try:
                    name = name.encode('cp437').decode('gbk')
                except (UnicodeEncodeError, UnicodeDecodeError):
                    pass
            name = name.replace('\\', '/')
            target = os.path.abspath(os.path.join(dest, name))
            if not (target == dest or target.startswith(dest + os.sep)):
                continue
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with z.open(info) as src, open(target, 'wb') as out:
                shutil.copyfileobj(src, out, 1 << 20)
            perm = (info.external_attr >> 16) & 0o7777
            if perm:
                try:
                    os.chmod(target, perm)
                except OSError:
                    pass
    return dest


def _index_subdirs(dirpath, dirnames):
    """列出该目录下所有旧索引子目录（00000000、00000001…）"""
    out = []
    for d in dirnames:
        if IDX_NAME_RE.match(d) and is_old_index(os.path.join(dirpath, d)):
            out.append(d)
    return out


def _has_image(dirpath, filenames):
    """该目录里是否有 SOMV 镜像或 vblock"""
    if 'vblock' in filenames:
        return True
    for fn in filenames:
        p = os.path.join(dirpath, fn)
        try:
            with open(p, 'rb') as f:
                if f.read(4) == MAGIC:
                    return True
        except OSError:
            continue
    return False


def find_partition_dirs(base):
    """找出所有分区目录，返回列表。

    判定：目录里出现 SOMV 镜像 / vblock / 旧索引目录，即为分区根。
    关键点：绝不能只看文件名含 '00000000' —— 索引目录里恰好有名为 00000000
    的索引文件，旧实现会把它当成分区根，打出来的包整体错位。
    """
    out = []
    for dirpath, dirnames, filenames in os.walk(base):
        idx = _index_subdirs(dirpath, dirnames)
        if idx or _has_image(dirpath, filenames):
            out.append(dirpath)
        # 索引目录内部不是分区，也不该继续下潜
        dirnames[:] = [d for d in dirnames if d not in idx]
    # 去掉"父目录也是分区"的重复项，保留最外层
    if len(out) > 1:
        keep = []
        for d in out:
            if not any(d != o and d.startswith(o + os.sep) for o in out):
                keep.append(d)
        out = keep
    return out


def find_image(pkg_dir):
    """目录里的 SOMV 镜像（优先 .so，其次任意名字）"""
    try:
        names = sorted(os.listdir(pkg_dir))
    except OSError:
        return None
    cands = []
    for fn in names:
        p = os.path.join(pkg_dir, fn)
        if not os.path.isfile(p):
            continue
        try:
            with open(p, 'rb') as f:
                if f.read(4) == MAGIC:
                    cands.append(p)
        except OSError:
            continue
    if not cands:
        return None
    if len(cands) > 1:
        # 多个镜像时选最大的（其余多为残留副本）
        cands.sort(key=os.path.getsize, reverse=True)
        print(f'  ⚠ 目录里有 {len(cands)} 个镜像，使用最大的 '
              f'{os.path.basename(cands[0])}')
    return cands[0]


def load_merged_ents(pkg_dir):
    """读出目录里所有索引分片并叠加合并：{inode: [(名字, 子inode)]}"""
    idx_dirs = _index_subdirs(pkg_dir, os.listdir(pkg_dir))
    if not idx_dirs:
        return {}
    merged = {}
    for d in idx_dirs:
        full = os.path.join(pkg_dir, d)
        try:
            names = os.listdir(full)
        except OSError:
            continue
        for fn in names:
            try:
                ino = int(fn, 16)
            except ValueError:
                continue
            slot = merged.setdefault(ino, {})
            try:
                with open(os.path.join(full, fn), 'rb') as f:
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


class ImageReader:
    """只读镜像，用于把"输入目录里只在镜像中的文件"补进树"""

    __slots__ = ('path', 'f', 'count', 'dsize', 'table', 'size')

    def __init__(self, path):
        self.path = path
        self.size = os.path.getsize(path)
        self.f = open(path, 'rb')
        hdr = self.f.read(HEAD)
        if hdr[:4] != MAGIC:
            self.f.close()
            raise ValueError('不是 SOMV 镜像: ' + path)
        _, self.count, self.dsize = struct.unpack_from('<III', hdr, 4)
        self.table = self.f.read(REC * self.count)

    def rec(self, ino):
        o = REC * ino
        if ino < 0 or o + REC > len(self.table):
            return None
        mode, = struct.unpack_from('<H', self.table, o)
        uid, gid = struct.unpack_from('<HH', self.table, o + 4)
        mt, = struct.unpack_from('<I', self.table, o + 24)
        size, = struct.unpack_from('<I', self.table, o + 28)
        off, = struct.unpack_from('<I', self.table, o + 32)
        return {'type': mode & S_IFMT, 'mode': mode & 0xFFFF,
                'uid': uid, 'gid': gid, 'mtime': mt, 'size': size, 'off': off}

    def read(self, ino):
        r = self.rec(ino)
        if not r or r['size'] == 0:
            return b''
        self.f.seek(r['off'])
        return self.f.read(r['size'])

    def read_to(self, ino, dst):
        r = self.rec(ino)
        if not r:
            return 0
        self.f.seek(r['off'])
        left = r['size']
        with open(dst, 'wb') as out:
            while left > 0:
                b = self.f.read(min(COPY_CHUNK, left))
                if not b:
                    break
                out.write(b)
                left -= len(b)
        return r['size'] - left

    def close(self):
        try:
            self.f.close()
        except OSError:
            pass


def merge_image_tree(root, pkg_dir, tmp_dir=None):
    """把镜像里独有的文件补进已扫描的树，磁盘上的明文优先。

    这一步不能省：原包目录的明文只是完整镜像的一部分（vendor 59/146），
    直接打包明文会把只在镜像里的文件静默丢掉。
    返回 (补充的文件数, 覆盖的元数据数)。
    """
    img_path = find_image(pkg_dir)
    ents = load_merged_ents(pkg_dir)
    if not img_path or not ents:
        return 0, 0

    img = ImageReader(img_path)
    index = {n.path: n for n in [root] + flatten(root)}
    added = 0
    touched = 0
    try:
        def walk(ino, pre, parent):
            nonlocal added, touched
            for name, child in ents.get(ino, []):
                p = pre + '/' + name
                r = img.rec(child)
                node = index.get(p)
                if node is None:
                    node = Node(p, name)
                    if r and r['type'] == S_IFDIR:
                        node.kind = S_IFDIR
                    elif r and r['type'] == S_IFLNK:
                        node.kind = S_IFLNK
                    else:
                        node.kind = S_IFREG
                    if r:
                        node.mode = r['mode']
                        # 大文件写到临时文件，避免几 GB 常驻内存
                        if r['size'] > LAZY_LIMIT and tmp_dir and node.kind == S_IFREG:
                            tmpf = os.path.join(tmp_dir, f'img_{child:08x}')
                            img.read_to(child, tmpf)
                            node.src = tmpf
                        else:
                            node.data = img.read(child)
                            if node.kind == S_IFLNK:
                                node.target = node.data.decode('utf-8', 'replace')
                    parent.children.append(node)
                    index[p] = node
                    added += 1
                if r:
                    if not node.uid and not node.gid:
                        node.uid, node.gid = r['uid'], r['gid']
                    if not node.mtime:
                        node.mtime = r['mtime']
                    touched += 1
                if r and r['type'] == S_IFDIR:
                    walk(child, p, node)
        walk(0, '', root)
    finally:
        img.close()
    return added, touched


def load_inherit(pkg_dir):
    """从原包目录读 path -> uid/gid/mtime/inode，供 --from 用。

    - 合并所有索引分片（00000000 + 00000001…），同名条目后者覆盖
    - 镜像用 mmap，2.6 GB 的 system 也不会整块读进内存
    """
    so = None
    for fn in sorted(os.listdir(pkg_dir)):
        p = os.path.join(pkg_dir, fn)
        if os.path.isfile(p):
            try:
                with open(p, 'rb') as f:
                    if f.read(4) == MAGIC:
                        so = p
                        break
            except OSError:
                pass
    if not so:
        return None
    idx_dirs = _index_subdirs(pkg_dir, os.listdir(pkg_dir))
    if not idx_dirs:
        return None

    merged = {}
    for d in idx_dirs:
        full = os.path.join(pkg_dir, d)
        for fn in os.listdir(full):
            try:
                ino = int(fn, 16)
            except ValueError:
                continue
            slot = merged.setdefault(ino, {})
            try:
                with open(os.path.join(full, fn), 'rb') as f:
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
    ents = {k: list(v.items()) for k, v in merged.items()}

    f = open(so, 'rb')
    try:
        try:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            closer = mm.close
        except (ValueError, OSError):
            mm = None
            closer = None
        meta = {}

        def mode_at(ino, b):
            return struct.unpack_from('<H', b, 0)[0]

        def rec_at(ino):
            o = HEAD + REC * ino
            if mm is not None:
                if o + REC > len(mm):
                    return None
                return mm[o:o + REC]
            f.seek(o)
            b = f.read(REC)
            return b if len(b) == REC else None

        root_rec = rec_at(0) if len(ents) else None
        if root_rec:
            uid, gid = struct.unpack_from('<HH', root_rec, 4)
            mt, = struct.unpack_from('<I', root_rec, 24)
            meta[''] = {'uid': uid, 'gid': gid, 'mtime': mt, 'ino': 0,
                        'mode': mode_at(0, root_rec)}

        def walk(ino, pre):
            for name, child in ents.get(ino, []):
                p = pre + '/' + name
                b = rec_at(child)
                if b:
                    uid, gid = struct.unpack_from('<HH', b, 4)
                    mt, = struct.unpack_from('<I', b, 24)
                    meta[p] = {'uid': uid, 'gid': gid, 'mtime': mt,
                               'ino': child, 'mode': mode_at(child, b)}
                if child in ents:
                    walk(child, p)
        walk(0, '')
        return meta
    finally:
        if closer:
            closer()
        f.close()


# ────────────────────────────── 主流程 ──────────────────────────────
def resolve_from(from_dir, name):
    """--from 既可以是某个分区目录，也可以是整包目录（按分区名匹配子目录）"""
    if not from_dir:
        return None
    d = os.path.abspath(from_dir)
    if not os.path.isdir(d):
        return None
    try:
        names = os.listdir(d)
    except OSError:
        return None
    if _index_subdirs(d, names):
        return d
    sub = os.path.join(d, name)
    if os.path.isdir(sub) and _index_subdirs(sub, os.listdir(sub)):
        return sub
    for cand in find_partition_dirs(d):
        if os.path.basename(cand.rstrip(os.sep)) == name:
            return cand
    return None


def clean_out(out_dir):
    """清掉上次打好的载体：.so、vblock、所有 hex 索引目录"""
    os.makedirs(out_dir, exist_ok=True)
    for fn in os.listdir(out_dir):
        p = os.path.join(out_dir, fn)
        if os.path.islink(p):
            os.unlink(p)          # 只删链接本身，不进目标
            continue
        if os.path.isfile(p):
            if fn == 'vblock':
                os.remove(p)
                continue
            try:
                with open(p, 'rb') as f:
                    is_img = f.read(4) == MAGIC
            except OSError:
                is_img = False
            if is_img:
                os.remove(p)
        elif os.path.isdir(p) and IDX_NAME_RE.match(fn) and is_old_index(p):
            shutil.rmtree(p)


def pack_one(pkg_dir, name, args, tmp_dir=None):
    """打包单个分区"""
    skip = set()
    try:
        entries = os.listdir(pkg_dir)
    except OSError as e:
        print(f'无法读取 {pkg_dir}: {e}')
        return None

    for fn in entries:
        p = os.path.join(pkg_dir, fn)
        if not os.path.isfile(p):
            continue
        if fn == 'vblock':
            skip.add(p)
            continue
        try:
            with open(p, 'rb') as f:
                is_img = f.read(4) == MAGIC
        except OSError:
            continue
        if is_img:
            skip.add(p)
            print(f'  忽略旧镜像 {fn}')

    old_idx = _index_subdirs(pkg_dir, entries)
    for d in old_idx:
        skip.add(os.path.join(pkg_dir, d))
    if old_idx:
        print(f'  忽略旧索引 {", ".join(sorted(old_idx))}/')

    links = load_links(pkg_dir)
    if links:
        print(f'  链接清单 _links.tsv: {len(links)} 条')
    root, skipped = scan(pkg_dir, skip, links)

    # 关键：目录里有镜像+索引时，先把只在镜像里的文件补进树，否则会静默丢文件
    added, _ = merge_image_tree(root, pkg_dir, tmp_dir)
    if added:
        print(f'  从镜像补回 {added} 个仅存在于镜像中的条目')

    inherit = None
    from_dir = resolve_from(args.from_dir, name)
    if not from_dir and old_idx:
        from_dir = pkg_dir          # 输入本身就是原包：自动继承 inode 与元数据
    if from_dir:
        inherit = load_inherit(from_dir)
        print(f'  继承元数据: {len(inherit) if inherit else 0} 条  ({from_dir})')
    elif args.from_dir:
        print(f'  ⚠ --from {args.from_dir} 里没找到 {name} 分区的索引，跳过继承')

    # 输入本身就是原包时，自动沿用原 inode 号：路径没变就能逐字节复现，
    # 新增文件会排到最大号之后，原有条目编号不动
    auto_keep = bool(from_dir) and os.path.abspath(from_dir) == os.path.abspath(pkg_dir)
    keep = None
    if args.keep_inode or auto_keep:
        if not inherit:
            print('  ⚠ 需要原索引才能沿用 inode 号，改用紧凑编号')
        else:
            keep = {k: v['ino'] for k, v in inherit.items()}
    count = assign_inodes(root, keep)
    nodes = flatten(root)
    nfile = sum(1 for n in nodes if not n.is_dir)
    nlink = sum(1 for n in nodes if n.is_link)

    out_dir = os.path.join(os.path.abspath(args.out), name)
    clean_out(out_dir)
    so_path = os.path.join(out_dir, '.so')
    # 先写临时文件再原子替换：就地覆盖时（-o 指向原包目录）中途失败不会毁掉原镜像
    tmp_so = so_path + '.tmp'
    data_size, nfile = build_image(root, count, tmp_so, args.mtime, inherit,
                                   meta_from_dir=getattr(args, 'meta_from_dir', False))
    os.replace(tmp_so, so_path)
    with open(os.path.join(out_dir, 'vblock'), 'wb') as f:
        f.write(build_vblock(count))
    write_index(root, out_dir)
    idx_list = index_files(out_dir)
    shards = sorted({d for d, _ in idx_list})
    if args.materialize:
        materialize(root, out_dir, getattr(args, 'links', 'text'))

    print(f'\n分区 {name}')
    print(f'  inode {count}（目录 {count - nfile} / 文件 {nfile}，其中链接 {nlink}）')
    print(f'  .so   {os.path.getsize(so_path):,} B   数据区 {data_size:,} B')
    print(f'  vblock 16 B')
    print(f'  索引   {len(idx_list)} 个目录文件，{len(shards)} 个分片'
          f'{("（" + "、".join(shards) + "）") if len(shards) > 1 else ""}')

    if skipped:
        print(f'\n跳过 {len(skipped)} 项:')
        for p, why in skipped[:8]:
            print(f'  - {p}  {why}')

    if not args.no_verify:
        ok, bad = verify(so_path, root)
        if ok:
            print('\n读回校验：✓ 全部文件内容、大小、inode 一致')
        else:
            print(f'\n读回校验：✗ {len(bad)} 处不符')
            for b in bad[:10]:
                print('  ', b)
            return None

    if args.zip:
        zp = os.path.join(os.path.abspath(args.out), f'{name}.zip')
        with zipfile.ZipFile(zp, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            for dirpath, dirnames, filenames in os.walk(out_dir):
                dirnames.sort()
                rel = os.path.relpath(dirpath, out_dir).replace(os.sep, '/')
                arc = name + '/' + ('' if rel == '.' else rel + '/')
                zi = zipfile.ZipInfo(arc)
                zi.external_attr = (0o40755 << 16) | 0x10
                z.writestr(zi, b'')
                for fn in sorted(filenames):
                    full = os.path.join(dirpath, fn)
                    info = zipfile.ZipInfo.from_file(full, arc + fn)
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.external_attr = (0o100644 << 16)
                    with open(full, 'rb') as fsrc, z.open(info, 'w') as fdst:
                        shutil.copyfileobj(fsrc, fdst, COPY_CHUNK)
        print(f'\n打包 {zp}  {os.path.getsize(zp):,} B')

    print(f'\n输出目录: {out_dir}')
    return out_dir


def main():
    ap = argparse.ArgumentParser(
        description='把目录或 zip 打包回 VMOS 分区格式（.so + vblock + 00000000）')
    ap.add_argument('src', help='要打包的目录，或包含该目录的 zip')
    ap.add_argument('-o', '--out', default='repack', help='输出目录（默认 repack）')
    ap.add_argument('--name', help='只打包指定名字的分区（默认全部）')
    ap.add_argument('--from', dest='from_dir', help='原分区目录或整包目录，继承 uid/gid/mtime/inode')
    ap.add_argument('--meta-from-dir', dest='meta_from_dir', action='store_true',
                    help='属主/权限按磁盘目录取，不继承原镜像（默认继承，避免解包工具把 755 变 644）')
    ap.add_argument('--mtime', type=int, help='统一时间戳（秒），默认沿用源文件')
    ap.add_argument('--zip', action='store_true', help='额外封装成 <name>.zip')
    ap.add_argument('--materialize', action='store_true', help='同时铺一份明文文件')
    ap.add_argument('--links', choices=('text', 'safe', 'raw'), default='text',
                    help='--materialize 时如何还原符号链接：text 只写占位（默认）、'
                         'safe 只建目录内相对链接、raw 建绝对链接（危险）')
    ap.add_argument('--keep-inode', action='store_true',
                    help='沿用原包 inode 号（配合 --from，可逐字节复现原镜像）')
    ap.add_argument('--no-verify', action='store_true', help='跳过打包后的读回校验')
    ap.add_argument('--keep-temp', action='store_true')
    ap.add_argument('--version', action='version',
                    version=f'vmos_pack {VERSION}  ({BUILD_NOTE})')
    args = ap.parse_args()

    src = os.path.abspath(args.src)
    if not os.path.exists(src):
        sys.exit(f'不存在: {src}')

    tmp = tempfile.mkdtemp(prefix='vmos_pack_')
    try:
        if zipfile.is_zipfile(src):
            print(f'解压 {os.path.basename(src)} ...')
            base = extract_zip(src, os.path.join(tmp, 'src'))
        else:
            base = src

        cands = find_partition_dirs(base)
        if not cands:
            print(f'⚠ 没找到镜像或索引，按普通目录处理: {base}')
            cands = [base]
        if args.name:
            picked = [c for c in cands
                      if os.path.basename(c.rstrip(os.sep)) == args.name]
            if not picked:
                sys.exit(f'没有名为 {args.name} 的分区。可选: '
                         + ', '.join(os.path.basename(c.rstrip(os.sep)) for c in cands))
            cands = picked
        elif len(cands) > 1:
            print(f'发现 {len(cands)} 个分区，逐个打包:')
            for c in cands:
                print('  -', c)

        used = {}
        ok_count = 0
        for pkg_dir in cands:
            name = os.path.basename(pkg_dir.rstrip(os.sep)) or 'partition'
            if name in used:                 # 同名的分区加序号，避免互相覆盖
                used[name] += 1
                name = f'{name}_{used[name]}'
            else:
                used[name] = 1
            if len(cands) > 1:
                print(f'\n{"=" * 56}')
            if pack_one(pkg_dir, name, args, tmp) is not None:
                ok_count += 1
        print(f'\n完成 {ok_count}/{len(cands)} 个分区，输出根目录: '
              f'{os.path.abspath(args.out)}')
    finally:
        if not args.keep_temp:
            shutil.rmtree(tmp, ignore_errors=True)
        else:
            print(f'临时目录: {tmp}')


if __name__ == '__main__':
    main()
