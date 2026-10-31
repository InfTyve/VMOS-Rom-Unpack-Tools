#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vmos_auto.py —— VMOS ROM 包全自动识别与还原
================================================================

喂什么都能吃：.zip / .7z / .tar(.gz) / 已解压目录，多层嵌套、多分区、无索引都行。

    python3 vmos_auto.py base_v10324.7z
    python3 vmos_auto.py root.zip -o ./out
    python3 vmos_auto.py 解压后的目录/
    python3 vmos_auto.py base_v10324.7z --probe        # 只看识别结果，不落地
    python3 vmos_auto.py x.zip --list-only             # 只列目录树

自动做的事
----------
1. 按内容（魔数 SOMV）找镜像，不看扩展名、不看大小、不限目录深度 ——
   root/root/.so、root/system/.so、libvmoskernel.so 之类都能认出来。
2. 按内容找目录索引：形如 <inode 16进制>=<inode 16进制> 的目录或单个文本文件。
3. 索引与镜像自动配对：算 inode 覆盖率，一个索引引用到多个镜像的 inode 时
   自动合并成多卷（root 骨架 + system 数据卷这种布局）。
4. 没有索引的镜像照样还原：按 inode 全量取出，ELF 用 DT_SONAME 找回真名，
   文本按内容分类，统一放进 _recovered/。

镜像格式
--------
  头 64B   "SOMV" | u32 版本 | u32 inode 数 | u32 数据区长度
  记录 44B  +0 u16 mode  +4 u16 uid  +6 u16 gid  +12 u32 nlink
            +16/20/24 atime/ctime/mtime  +28 u32 size  +32 u32 offset
  数据区   紧接记录表向上取整到 4096，每个文件按 4096 对齐
  索引     每个目录一个文件，名=inode(8位hex)，内容 "名字=inode(hex)"，CRLF 换行
"""

import argparse
import json
import mmap
import os
import re
import shutil
import struct
import sys
import tarfile
import tempfile
import time
import zipfile

VERSION = '2026.10.31.3'
BUILD_NOTE = '无索引包平铺恢复 + SONAME 重名不再互相覆盖 + 清单带 inode 列'

REC_SIZE = 44
HEAD_SIZE = 64
MAGIC = b'SOMV'
VB_MAGIC = b'KLBV'

S_IFMT, S_IFDIR, S_IFREG, S_IFLNK = 0xF000, 0x4000, 0x8000, 0xA000
S_IFCHR, S_IFBLK, S_IFIFO, S_IFSOCK = 0x2000, 0x6000, 0x1000, 0xC000
TYPE_NAME = {S_IFDIR: 'dir', S_IFREG: 'file', S_IFLNK: 'link', S_IFCHR: 'chr',
             S_IFBLK: 'blk', S_IFIFO: 'fifo', S_IFSOCK: 'sock'}


# ────────────────────────────── 镜像 ──────────────────────────────
class Image:
    """一个 SOMV 镜像（mmap 只读，GB 级也不吃内存）"""

    def __init__(self, path):
        self.path = path
        self.size = os.path.getsize(path)
        self.f = open(path, 'rb')
        self.data = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        if self.data[:4] != MAGIC:
            raise ValueError(f'{path} 不是 SOMV 镜像')
        self.version, self.count, self.data_size = struct.unpack('<III', self.data[4:16])
        max_rec = (self.size - HEAD_SIZE) // REC_SIZE
        self.count_declared = self.count
        if self.count > max_rec:
            self.count = max_rec
        self.recs = {}
        for i in range(self.count):
            self.recs[i] = self._parse(HEAD_SIZE + REC_SIZE * i)
        self._validate()

    def _parse(self, off):
        d = self.data
        mode, = struct.unpack_from('<H', d, off)
        uid, gid = struct.unpack_from('<HH', d, off + 4)
        nlink, = struct.unpack_from('<I', d, off + 12)
        atime, ctime, mtime = struct.unpack_from('<III', d, off + 16)
        size, = struct.unpack_from('<I', d, off + 28)
        doff, = struct.unpack_from('<I', d, off + 32)
        return {'mode': mode, 'perm': mode & 0o7777, 'type': mode & S_IFMT,
                'uid': uid, 'gid': gid, 'nlink': nlink, 'atime': atime,
                'ctime': ctime, 'mtime': mtime, 'size': size, 'offset': doff}

    def _validate(self):
        """记录表是否像模像样：用于在格式变体时给出提示"""
        if not self.recs:
            self.valid_ratio = 0.0
            return
        good = 0
        for r in self.recs.values():
            if r['type'] in (S_IFDIR, S_IFREG, S_IFLNK, S_IFCHR, S_IFBLK,
                             S_IFIFO, S_IFSOCK) and r['perm'] <= 0o7777:
                good += 1
        self.valid_ratio = good / len(self.recs)

    def inodes(self):
        return set(self.recs)

    def read(self, ino):
        r = self.recs.get(ino)
        if not r:
            return None
        s, o = r['size'], r['offset']
        if s == 0:
            return b''
        if o + s > self.size:
            return None
        return self.data[o:o + s]

    def close(self):
        try:
            if not self.data.closed:
                self.data.close()
        except (ValueError, BufferError):
            pass
        try:
            self.f.close()
        except OSError:
            pass


class Volumes:
    """一个分区的全部镜像卷：按 inode 逐个卷尝试读取"""

    def __init__(self, images):
        self.images = sorted(images, key=lambda x: x.size, reverse=True)
        self.recs = {}
        self.overlap = 0
        for im in self.images:
            for i, r in im.recs.items():
                if i in self.recs:
                    self.overlap += 1
                else:
                    self.recs[i] = r
        self.count = len(self.recs)
        self.size = sum(im.size for im in self.images)
        self.version = self.images[0].version
        self.path = ' + '.join(os.path.basename(i.path) for i in self.images)

    def read(self, ino):
        for im in self.images:
            if ino in im.recs:
                blob = im.read(ino)
                if blob is not None:
                    return blob
        return None

    def head(self, ino, n=1 << 20):
        """只读文件开头，用于识别类型/校验，避免为判断类型读整个文件"""
        for im in self.images:
            if ino in im.recs:
                r = im.recs[ino]
                if r['size'] == 0:
                    return b''
                if r['offset'] + r['size'] > im.size:
                    return None
                return bytes(im.data[r['offset']:r['offset'] + min(n, r['size'])])
        return None

    def copy_to(self, ino, fp, chunk=1 << 20):
        """把文件内容分块写进 fp，内存占用与文件大小无关（system 有 2.6 GB）"""
        for im in self.images:
            if ino in im.recs:
                r = im.recs[ino]
                if r['size'] == 0:
                    return 0
                if r['offset'] + r['size'] > im.size:
                    return None
                off, left = r['offset'], r['size']
                drop = getattr(im.data, 'madvise', None)
                while left > 0:
                    n = min(chunk, left)
                    b = im.data[off:off + n]
                    if not b:
                        break
                    fp.write(b)
                    # 读完立刻让内核回收这一段的页，避免 RSS 跟着文件大小涨
                    if drop:
                        try:
                            drop(mmap.MADV_DONTNEED, off, len(b))
                        except (OSError, ValueError):
                            drop = None
                    off += len(b)
                    left -= len(b)
                return r['size'] - left
        return None

    def close(self):
        for im in self.images:
            try:
                im.close()
            except Exception:
                pass


def doctor_report(images, indexes, log):
    """只读诊断：不落地，检查记录表与数据区是否自洽"""
    log('\n' + '=' * 62)
    log('镜像诊断（只读）')
    for im in images:
        files = [r for r in im.recs.values()
                 if r['type'] == S_IFREG and r['size'] > 0]
        dirs = sum(1 for r in im.recs.values() if r['type'] == S_IFDIR)
        links = sum(1 for r in im.recs.values() if r['type'] == S_IFLNK)
        data_start = (HEAD_SIZE + REC_SIZE * im.count + 4095) // 4096 * 4096
        oob = sum(1 for r in files if r['offset'] + r['size'] > im.size)
        low = sum(1 for r in files if r['offset'] < data_start)
        zero = sum(1 for r in files if r['offset'] == 0)
        ext = sorted((r['offset'], r['size']) for r in files)
        overlap = 0
        prev_end = data_start
        max_gap = 0
        for off, size in ext:
            if off < prev_end:
                overlap += 1
            elif off - prev_end > max_gap:
                max_gap = off - prev_end
            prev_end = max(prev_end, off + size)
        # 数据区是否够装：size 之和 + 每个文件最多 4095B 对齐
        need_min = sum(r['size'] for r in files)
        need_max = need_min + len(files) * 4095
        log(f'\n  {os.path.basename(im.path)}  {im.size:,} B')
        log(f'    版本 {im.version}  inode {im.count}/{im.count_declared}  '
            f'数据区声明 {im.data_size:,}  B  实际可用 {im.size - data_start:,} B')
        log(f'    目录 {dirs}  文件 {len(files)}  链接 {links}  '
            f'记录合法率 {im.valid_ratio:.1%}')
        log(f'    文件大小合计 {need_min:,} B  含对齐上限 {need_max:,} B')
        log(f'    越界 {oob}  起点早于数据区 {low}  offset=0 {zero}  '
            f'区间重叠 {overlap}  最大空隙 {max_gap:,} B')
        for tag, val, bad in (('越界', oob, oob), ('起点非法', low, low),
                              ('区间重叠', overlap, overlap)):
            if bad:
                log(f'    ⚠ {tag}: {val} 条，说明记录表/数据区模型不适用或有缺失')
    if indexes:
        log('\n  索引覆盖：')
        for desc, ents in indexes:
            refs = _refs_of(ents)
            best = max(images, key=lambda im: len(refs & im.inodes()), default=None)
            cov = len(refs & best.inodes()) if best else 0
            log(f'    {desc}  引用 {len(refs)}  inode  '
                f'→ {os.path.basename(best.path) if best else "-"} 覆盖 {cov}')
    log('=' * 62)


# ────────────────────────────── 解压 ──────────────────────────────
def _fix_zip_name(info):
    if info.flag_bits & 0x800:
        return info.filename
    try:
        raw = info.filename.encode('cp437')
    except UnicodeEncodeError:
        return info.filename
    for enc in ('utf-8', 'gbk'):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return info.filename


def extract_zip(path, dest):
    dest = os.path.abspath(dest)
    with zipfile.ZipFile(path) as z:
        total = sum(i.file_size for i in z.infolist())
        done = 0
        mark = 0
        for info in z.infolist():
            name = _fix_zip_name(info).replace('\\', '/')
            target = os.path.abspath(os.path.join(dest, name))
            if not (target == dest or target.startswith(dest + os.sep)):
                continue
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with z.open(info) as src, open(target, 'wb') as out:
                shutil.copyfileobj(src, out, 1 << 20)
            done += info.file_size
            if total > 200 << 20 and done - mark > 200 << 20:
                mark = done
                print(f'    ... {done >> 20} MB / {total >> 20} MB', flush=True)
            perm = (info.external_attr >> 16) & 0o7777
            if perm:
                try:
                    os.chmod(target, perm)
                except OSError:
                    pass
    return dest


def extract_7z(path, dest):
    exe = shutil.which('7z') or shutil.which('7za') or shutil.which('7zr')
    if exe:
        import subprocess
        os.makedirs(dest, exist_ok=True)
        r = subprocess.run([exe, 'x', '-y', f'-o{dest}', path],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if r.returncode not in (0, 1):
            raise RuntimeError(r.stdout.decode('utf-8', 'replace')[:500])
        return dest
    try:
        import py7zr
    except ImportError:
        raise RuntimeError(
            '需要 7z 支持：装 p7zip（apt install p7zip-full）或 pip install py7zr，\n'
            '也可以先用 MT/电脑把 .7z 解压成目录，再把目录喂给本脚本')
    os.makedirs(dest, exist_ok=True)
    with py7zr.SevenZipFile(path, 'r') as z:
        z.extractall(dest)
    return dest


def extract_tar(path, dest):
    os.makedirs(dest, exist_ok=True)
    with tarfile.open(path) as t:
        t.extractall(dest, filter='data')
    return dest


def materialize(src, dest):
    ext = os.path.splitext(src)[1].lower()
    if zipfile.is_zipfile(src):
        return extract_zip(src, dest)
    if src.lower().endswith('.7z'):
        return extract_7z(src, dest)
    if ext in ('.tar', '.gz', '.tgz', '.xz', '.bz2') or src.lower().endswith('.tar.gz'):
        return extract_tar(src, dest)
    raise RuntimeError(f'不认识的压缩格式: {os.path.basename(src)}')


# ────────────────────────────── 探测 ──────────────────────────────
def sniff_magic(path, n=4):
    try:
        with open(path, 'rb') as f:
            return f.read(n)
    except OSError:
        return b''


def index_lines(raw):
    """解析索引文本为 [(name, ino)]；不像索引则返回 None"""
    items = []
    good = bad = 0
    for line in raw.decode('utf-8', 'replace').splitlines():
        line = line.strip()
        if not line:
            continue
        if '=' not in line:
            bad += 1
            continue
        name, child = line.rsplit('=', 1)
        try:
            items.append((name.strip(), int(child, 16)))
            good += 1
        except ValueError:
            bad += 1
    if good < 1 or good < bad:
        return None
    return items


def is_index_dir(d):
    try:
        names = [n for n in os.listdir(d) if os.path.isfile(os.path.join(d, n))]
    except OSError:
        return False
    if not names:
        return False
    hexn = 0
    for n in names:
        try:
            int(n, 16)
            hexn += 1
        except ValueError:
            pass
    if hexn < max(1, len(names) // 2):
        return False
    hits = 0
    for n in names[:6]:
        try:
            with open(os.path.join(d, n), 'rb') as f:
                head = f.read(8192)
        except OSError:
            continue
        if index_lines(head) is not None:
            hits += 1
    return hits > 0


def index_tree(items):
    """单文件索引展开成目录树；条目名含 / 时按层级合成虚拟目录（负数 inode）"""
    if not any('/' in n for n, _ in items):
        return {0: items}
    ents = {0: []}
    made = {}
    nxt = -2
    for name, ino in items:
        parts = [x for x in name.strip().strip('/').split('/') if x]
        if not parts:
            continue
        cur = 0
        for i, part in enumerate(parts):
            if i == len(parts) - 1:
                ents.setdefault(cur, []).append((part, ino))
            else:
                key = '/'.join(parts[:i + 1])
                child = made.get(key)
                if child is None:
                    child = nxt
                    nxt -= 1
                    made[key] = child
                    ents.setdefault(cur, []).append((part, child))
                    ents[child] = []
                cur = child
    return ents


def load_index_dir(d):
    """{目录 inode: [(名字, 子 inode)]}"""
    ents = {}
    for fn in os.listdir(d):
        p = os.path.join(d, fn)
        if not os.path.isfile(p):
            continue
        try:
            ino = int(fn, 16)
        except ValueError:
            continue
        try:
            with open(p, 'rb') as f:
                items = index_lines(f.read()) or []
        except OSError:
            items = []
        ents[ino] = items
    return ents


def sniff(root, log=None):
    """全树扫描：先找索引目录，再扫文件（跳过索引目录内部，避免把索引当数据）"""
    images, idx_dirs, idx_files = _scan(root)

    # 同目录下还留着上次解包的 vmos_out/：只有「外面也有镜像」时才把它当残留忽略。
    # 如果整包内容本身就被包在 vmos_out/ 这一层里，照常识别（否则会 0/0/0）。
    def in_out(p):
        return any(seg == 'vmos_out' for seg in p.split(os.sep))

    fi = [p for p in images if not in_out(p)]
    fd = [p for p in idx_dirs if not in_out(p)]
    ff = [p for p in idx_files if not in_out(p)]
    if fi and (len(fi) < len(images) or len(fd) < len(idx_dirs)):
        if log:
            log(f'  忽略上次解包残留：镜像 {len(images) - len(fi)} 个 / '
                f'索引目录 {len(idx_dirs) - len(fd)} 个（在 vmos_out/ 里）')
        return fi, fd, ff
    return images, idx_dirs, idx_files


def _scan(root):
    images, idx_dirs, idx_files = [], [], []
    dirs_seen = []

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in ('__MACOSX', '.git', 'node_modules')]
        for d in list(dirnames):
            p = os.path.join(dirpath, d)
            if is_index_dir(p):
                idx_dirs.append(p)
                dirs_seen.append(p)

    def inside_index(path):
        for d in dirs_seen:
            if path.startswith(d + os.sep):
                return True
        return False

    def is_index_entry(parent, name):
        """索引目录里只有 8 位 hex 文件才是索引本身。
        其它文件（.vmos_exec_overlay 之类）是旁挂数据，不能当索引丢掉。"""
        try:
            int(name, 16)
            return len(name) == 8
        except ValueError:
            return False

    def consider(p, fn):
        try:
            sz = os.path.getsize(p)
        except OSError:
            return
        if sz < 16:
            return
        if sniff_magic(p, 4) == MAGIC:
            images.append(p)
            return
        try:
            int(os.path.splitext(fn)[0], 16)
            return
        except ValueError:
            pass
        if sz > 64 << 20:
            return
        try:
            with open(p, 'rb') as f:
                raw = f.read(min(sz, 4 << 20))
        except OSError:
            return
        if b'\x00' in raw[:1024]:
            return
        items = index_lines(raw)
        if items and len(items) >= 20:
            idx_files.append(p)

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in ('__MACOSX', '.git', 'node_modules')]
        if dirpath in dirs_seen:
            # 索引目录本身：跳过 hex 索引文件，其它文件照常当数据
            for fn in filenames:
                if not is_index_entry(dirpath, fn):
                    consider(os.path.join(dirpath, fn), fn)
            dirnames[:] = []
            continue
        if inside_index(dirpath):
            dirnames[:] = []
            continue
        for fn in filenames:
            consider(os.path.join(dirpath, fn), fn)
    return images, idx_dirs, idx_files


def group_indexes(indexes):
    """同一分区目录下的多个索引（00000000、00000001…）是分片/叠加层，合并成一份。

    同名条目以后出现的分片为准（00000001 覆盖 00000000），与叠加层语义一致。
    返回 [(代表 desc, 合并后的 ents, [分片 desc], 冲突条数)]
    """
    groups = {}
    for desc, ents in indexes:
        parent = os.path.dirname(desc.rstrip('/'))
        groups.setdefault(parent, []).append((desc, ents))

    out = []
    for parent, items in groups.items():
        items.sort(key=lambda x: x[0])
        if len(items) == 1:
            desc, ents = items[0]
            out.append((desc, ents, [desc], 0))
            continue
        merged = {}
        conflicts = 0
        for desc, ents in items:
            for ino, lst in ents.items():
                slot = merged.setdefault(ino, {})
                for name, child in lst:
                    if name in slot and slot[name] != child:
                        conflicts += 1
                    slot[name] = child
        flat = {ino: list(slot.items()) for ino, slot in merged.items()}
        out.append((items[0][0], flat, [d for d, _ in items], conflicts))
    return out


def _refs_of(ents):
    refs = set(ents)
    for items in ents.values():
        refs.update(c for _, c in items)
    return refs


def pair(images, indexes, log):
    """索引 ↔ 镜像配对。

    规则优先级：
      1. 索引目录与镜像在同一个分区目录（root/system/00000000 ↔ root/system/.so）
         —— 这是最强证据，直接配对，多个分片先合并；
      2. 同目录没有镜像时，才退回 inode 覆盖率，且优先"覆盖率相同但多余 inode 最少"
         的镜像，避免大镜像把别人的索引抢走；
      3. 每个镜像只能用一次，绝不复用。
    """
    groups = group_indexes(indexes)
    jobs = []
    used = set()

    def covered_of(group, refs):
        cov = set()
        for i in group:
            cov |= refs & images[i].inodes()
        return cov

    # 1) 按目录就近配对
    pending = []
    for desc, ents, shards, conflicts in groups:
        refs = _refs_of(ents)
        parent = os.path.dirname(desc.rstrip('/'))
        local = [i for i, im in enumerate(images)
                 if i not in used and os.path.dirname(im.path) == parent]
        if not local:
            pending.append((desc, ents, shards, conflicts, refs))
            continue
        local.sort(key=lambda i: len(refs & images[i].inodes()), reverse=True)
        group = [local[0]]
        covered = refs & images[local[0]].inodes()
        # 同目录还有别的卷，且确实能补上 >2% 的 inode，才算多卷
        for i in local[1:]:
            add = refs & images[i].inodes()
            if len(add - covered) > 0.02 * max(1, len(refs)):
                group.append(i)
                covered |= add
        used.update(group)
        jobs.append({'desc': desc, 'group': group, 'ents': ents,
                     'refs': refs, 'covered': covered, 'shards': shards,
                     'conflicts': conflicts})

    # 2) 没有同目录镜像的索引，退回覆盖率
    for desc, ents, shards, conflicts, refs in pending:
        cand = [i for i in range(len(images)) if i not in used]
        if not cand:
            jobs.append({'desc': desc, 'group': [], 'ents': ents,
                         'refs': refs, 'covered': set(), 'shards': shards,
                         'conflicts': conflicts})
            continue
        def score(i):
            cov = len(refs & images[i].inodes())
            ratio = cov / max(1, len(refs))
            excess = len(images[i].inodes()) - cov
            return (ratio, -excess, cov)
        cand.sort(key=score, reverse=True)
        best = cand[0]
        if len(refs & images[best].inodes()) == 0:
            jobs.append({'desc': desc, 'group': [], 'ents': ents,
                         'refs': refs, 'covered': set(), 'shards': shards,
                         'conflicts': conflicts})
            continue
        group = [best]
        covered = refs & images[best].inodes()
        for i in cand[1:]:
            add = refs & images[i].inodes()
            if len(add - covered) > 0.02 * max(1, len(refs)):
                group.append(i)
                covered |= add
        used.update(group)
        jobs.append({'desc': desc, 'group': group, 'ents': ents,
                     'refs': refs, 'covered': covered, 'shards': shards,
                     'conflicts': conflicts})

    # 3) 剩下的镜像没有索引，按 inode 全量恢复
    for i in range(len(images)):
        if i not in used:
            jobs.append({'desc': None, 'group': [i], 'ents': None,
                         'refs': set(), 'covered': set(), 'shards': [],
                         'conflicts': 0})
    return jobs


def part_name(desc, group, images, root):
    if desc:
        parent = os.path.dirname(desc)
        if os.path.basename(desc) == '00000000':
            parent = os.path.dirname(desc)
        name = os.path.basename(parent.rstrip(os.sep))
    else:
        name = os.path.basename(os.path.dirname(images[group[0]].path).rstrip(os.sep))
    name = re.sub(r'^\d{10,}[-_]', '', name or '').strip(' .')
    if not name or re.fullmatch(r'[0-9a-fA-F]{2,16}', name):
        name = os.path.basename(os.path.dirname(os.path.dirname(desc or ''))) or 'partition'
    return name or 'partition'


# ────────────────────────────── 名字兜底 ──────────────────────────────
def suspect_reason(path, blob):
    """按扩展名做最低限度校验，用来发现"切错数据"的文件"""
    ext = os.path.splitext(path)[1].lower()
    if not blob:
        return None
    if ext == '.so' and not blob.startswith(b'\x7fELF'):
        return '不是 ELF'
    if ext in ('.apk', '.jar', '.zip') and not blob.startswith(b'PK'):
        return '不是 ZIP'
    if ext == '.dex' and not blob.startswith(b'dex\n'):
        return '不是 DEX'
    if ext == '.png' and not blob.startswith(b'\x89PNG'):
        return '不是 PNG'
    if ext in ('.jpg', '.jpeg') and not blob.startswith(b'\xff\xd8'):
        return '不是 JPEG'
    if ext == '.xml' and b'<' not in blob[:256]:
        return '不是 XML'
    if ext in ('.rc', '.prop', '.conf', '.cfg', '.json', '.txt', '.sh') \
            and b'\x00' in blob[:512]:
        return '含 NUL，疑似二进制'
    return None


def guess_ext(blob):
    if not blob:
        return '.empty'
    if blob[:4] == b'\x7fELF':
        return '.so'
    if blob[:4] == b'PK\x03\x04':
        if b'AndroidManifest.xml' in blob[:200000]:
            return '.apk'
        return '.zip'
    if blob[:8] == b'\x89PNG\r\n\x1a\n':
        return '.png'
    if blob[:3] == b'\xff\xd8\xff':
        return '.jpg'
    if blob[:1] == b'<':
        return '.xml'
    if blob[:4] == b'\x1f\x8b\x08\x00':
        return '.gz'
    head = blob[:4096]
    if b'\x00' not in head:
        txt = head.decode('utf-8', 'replace')
        if 'service ' in txt or txt.lstrip().startswith('on ') or '\nimport ' in txt:
            return '.rc'
        if '(allow ' in txt or '\ntype ' in txt or '(neverallow ' in txt:
            return '.te'
        if 'ro.' in txt or 'persist.' in txt:
            return '.prop'
        if '=' in txt or txt.startswith('#') or '\n' in txt:
            return '.txt'
    return '.bin'


def elf_name(blob):
    """从 ELF 的 DT_SONAME 取真名；取不到再从字符串表里找 lib*.so"""
    try:
        if blob[:4] != b'\x7fELF':
            return None
        cls, enc = blob[4], blob[5]
        e = '<' if enc == 1 else '>'
        if cls == 2:
            e_phoff, = struct.unpack_from(e + 'Q', blob, 0x20)
            e_phentsize, e_phnum = struct.unpack_from(e + 'HH', blob, 0x36)
        else:
            e_phoff, = struct.unpack_from(e + 'I', blob, 0x1C)
            e_phentsize, e_phnum = struct.unpack_from(e + 'HH', blob, 0x2A)
        strtab = soname = None
        for i in range(e_phnum):
            q = e_phoff + i * e_phentsize
            p_type, = struct.unpack_from(e + 'I', blob, q)
            if p_type != 2:
                continue
            if cls == 2:
                off, = struct.unpack_from(e + 'Q', blob, q + 8)
                fsz, = struct.unpack_from(e + 'Q', blob, q + 32)
            else:
                off, = struct.unpack_from(e + 'I', blob, q + 4)
                fsz, = struct.unpack_from(e + 'I', blob, q + 16)
            step = 16 if cls == 2 else 8
            for k in range(0, fsz, step):
                if off + k + step > len(blob):
                    break
                tag, = struct.unpack_from(e + ('Q' if cls == 2 else 'I'), blob, off + k)
                val, = struct.unpack_from(e + ('Q' if cls == 2 else 'I'), blob,
                                          off + k + step // 2)
                if tag == 5:
                    strtab = val
                elif tag == 14:
                    soname = val
                elif tag == 0:
                    break
            break
        if strtab is not None and soname is not None:
            end = blob.find(b'\x00', strtab + soname)
            name = blob[strtab + soname:end].decode('utf-8', 'replace')
            if name and '/' not in name and len(name) < 128:
                return name
    except Exception:
        pass
    for m in re.finditer(rb'[A-Za-z0-9_+.@-]{3,60}\.so', blob[:2 << 20]):
        s = m.group().decode('ascii', 'replace')
        if not s.startswith('lib'):
            continue
        return s
    return None


# ────────────────────────────── 还原 ──────────────────────────────
def is_within(base, path):
    base = os.path.realpath(base)
    p = os.path.realpath(path)
    return p == base or p.startswith(base + os.sep)


def ensure_dir(base, path):
    """逐级建目录。遇到同名符号链接只删链接本身，绝不沿链接写进目标。"""
    base = os.path.abspath(base)
    path = os.path.abspath(path)
    # 先用字面路径判断，不能 realpath：旧链接会把它解析到目录外
    try:
        if os.path.commonpath([base, path]) != base:
            raise OSError('拒绝写到输出目录之外: ' + path)
    except ValueError:
        raise OSError('路径不在输出目录内: ' + path)
    rel = os.path.relpath(path, base)
    # base 本身也要建：分区目录不存在时（包内第一个条目就是文件），
    # 下面只建 rel 部分，open() 会直接 FileNotFoundError
    if not os.path.isdir(base):
        os.makedirs(base, exist_ok=True)
    cur = base
    for part in ([] if rel == '.' else rel.split(os.sep)):
        cur = os.path.join(cur, part)
        if os.path.islink(cur):
            os.unlink(cur)
        elif os.path.exists(cur) and not os.path.isdir(cur):
            os.unlink(cur)
        if not os.path.isdir(cur):
            os.mkdir(cur)
    if not is_within(base, cur):
        raise OSError('路径解析到输出目录之外: ' + cur)


def link_is_safe(base, path, target):
    """相对链接且解析后仍在输出目录内才算安全"""
    if not target or os.path.isabs(target):
        return False
    return is_within(base, os.path.join(os.path.dirname(path), target))


LINK_TSV = '_links.tsv'
LINK_NOTE = ('# 本文件是符号链接占位，不是真实文件\n'
             '# 原链接指向: %s\n'
             '# 未创建真实链接，防止在本机跟随到存储目录。\n'
             '# 打包时会读取 _links.tsv 还原为原链接。\n')


def build_tree(ents):
    tree = []

    def walk(ino, prefix, seen):
        for name, child in ents.get(ino, []):
            p = prefix + '/' + name
            child_is_dir = child in ents
            tree.append((p, child, child_is_dir))
            if child_is_dir and child not in seen:
                seen.add(child)
                walk(child, p, seen)
    walk(0, '', {0})
    return tree


def restore(job, images, out_dir, opts, log):
    vols = Volumes(images)
    ents = job['ents']
    stats = {'dir': 0, 'file': 0, 'link': 0, 'recovered': 0,
             'missing': 0, 'bytes': 0, 'suspect': 0, 'zero_tail': 0,
             'volume': len(job['group'])}
    rows = []
    links = []
    parents = set()

    if ents is not None:
        tree = build_tree(ents)
    else:
        tree = []

    used = {c for _, c, _ in tree}
    for p, _, _ in tree:
        parts = p.strip('/').split('/')
        for k in range(1, len(parts)):
            parents.add('/' + '/'.join(parts[:k]))

    def write_file(dst, ino, rec):
        """流式写盘：system 里的单文件可能有几百 MB，不能整块读进内存"""
        ensure_dir(out_dir, os.path.dirname(dst))
        if os.path.islink(dst):
            os.unlink(dst)
        with open(dst, 'wb') as f:
            n = vols.copy_to(ino, f)
            if n is None:
                raise OSError('数据越界')
        # 尾部全 0 = 镜像里这块没写数据，是打包出错最典型的症状，顺手记一笔
        if n and rec['size'] >= (64 << 10):
            try:
                with open(dst, 'rb') as f:
                    f.seek(-96, 2)
                    if f.read(96).count(0) == 96:
                        stats['zero_tail'] += 1
            except OSError:
                pass
        _meta(dst, rec, opts)

    for path, ino, is_dir in tree:
        rec = vols.recs.get(ino)
        dst = os.path.join(out_dir, path.lstrip('/'))
        # 索引缺这一层时（目录没自己的索引文件），靠 inode 记录的类型兜底
        if is_dir or (rec and rec['type'] == S_IFDIR):
            stats['dir'] += 1
            if not opts.list_only:
                os.makedirs(dst, exist_ok=True)
            rows.append({'path': path, 'inode': ino, 'type': 'dir', 'state': 'dir'})
            continue
        if rec is None:
            stats['missing'] += 1
            rows.append({'path': path, 'inode': ino, 'type': '?', 'state': 'no-inode'})
            continue
        if rec['type'] == S_IFLNK:
            target = vols.read(ino) or b''
            stats['link'] += 1
            rows.append({'path': path, 'inode': ino, 'type': 'link', 'state': 'link',
                         'size': len(target),
                         'target': target.decode('utf-8', 'replace')})
            target_text = target.decode('utf-8', 'replace')
            links.append((path, target_text))
            if opts.list_only:
                continue
            ensure_dir(out_dir, os.path.dirname(dst))
            if os.path.lexists(dst):
                os.unlink(dst)          # 只删链接/文件本身
            mode = getattr(opts, 'link_mode', 'text')
            if mode == 'raw' or (mode == 'safe' and link_is_safe(out_dir, dst, target_text)):
                try:
                    os.symlink(target_text, dst)
                    continue
                except OSError:
                    pass
            # 默认 text：写占位文件，绝不在本机建立指向 /system、/storage 的链接
            if path not in parents:
                with open(dst, 'wb') as f:
                    f.write((LINK_NOTE % target_text).encode('utf-8'))
            continue
        head = vols.head(ino)
        if head is None:
            stats['missing'] += 1
            rows.append({'path': path, 'inode': ino,
                         'type': TYPE_NAME.get(rec['type'], '?'),
                         'state': 'data-missing', 'size': rec['size']})
            continue
        stats['file'] += 1
        stats['bytes'] += rec['size']
        rows.append({'path': path, 'inode': ino,
                     'type': TYPE_NAME.get(rec['type'], 'file'), 'state': 'ok',
                     'size': rec['size'], 'mode': oct(rec['mode'])})
        why = suspect_reason(path, head)
        if why:
            stats['suspect'] += 1
            rows[-1]['suspect'] = why
        if not opts.list_only:
            write_file(dst, ino, rec)

    # 索引没提到的 inode：数据还在，只是丢了名字和层级
    orphans = [i for i in vols.recs if i not in used and i != 0
               and vols.recs[i]['type'] != S_IFDIR
               and not (vols.recs[i]['size'] == 0 and not ents)]
    if orphans and not opts.no_recover:
        rec_dir = os.path.join(out_dir, '_recovered')
        if not opts.list_only:
            os.makedirs(rec_dir, exist_ok=True)
        seen_names = set()
        for ino in orphans:
            rec = vols.recs[ino]
            blob = vols.head(ino)
            if blob is None:
                stats['missing'] += 1
                continue
            if rec['type'] == S_IFLNK:
                name = f'inode_{ino:08x}.link'
                target_text = blob.decode('utf-8', 'replace')
            else:
                target_text = None
                base = (elf_name(blob) if blob[:4] == b'\x7fELF' else None) \
                    or f'inode_{ino:08x}{guess_ext(blob)}'
                # 不同 inode 可能撞上同一个 SONAME（同一个库的多个副本），
                # 直接同名会互相覆盖、静默丢文件，所以撞名就带 inode 号
                name, n = base, 2
                while name in seen_names:
                    stem, ext2 = os.path.splitext(base)
                    name = f'{stem}__{ino:08x}{ext2}' if n == 2 \
                        else f'{stem}__{ino:08x}_{n}{ext2}'
                    n += 1
                seen_names.add(name)
            stats['recovered'] += 1
            stats['bytes'] += rec['size']
            rows.append({'path': '/_recovered/' + name, 'inode': ino,
                         'type': TYPE_NAME.get(rec['type'], 'file'),
                         'state': 'recovered', 'size': rec['size'],
                         'target': target_text})
            if opts.list_only:
                continue
            dst = os.path.join(rec_dir, name)
            if rec['type'] == S_IFLNK:
                links.append(('/_recovered/' + name, target_text))
                # 孤儿链接一律落成文本，连相对链接也不建
                try:
                    if os.path.lexists(dst):
                        os.unlink(dst)
                    with open(dst, 'wb') as f:
                        f.write(blob)
                except OSError:
                    pass
                continue
            ensure_dir(out_dir, os.path.dirname(dst))
            if os.path.islink(dst):
                os.unlink(dst)
            with open(dst, 'wb') as f:
                vols.copy_to(ino, f)
            _meta(dst, rec, opts)

    if links and not opts.list_only:
        try:
            tsv = os.path.join(out_dir, LINK_TSV)
            if os.path.islink(tsv):
                os.unlink(tsv)
            with open(tsv, 'w', encoding='utf-8') as f:
                f.write('# VMOS 符号链接清单（相对路径<TAB>目标）\n')
                f.write('# 默认不创建真实链接；打包 vmos_pack.py 会据此还原\n')
                for pth, tgt in sorted(links):
                    f.write(f'{pth.lstrip("/")}\t{tgt}\n')
        except OSError:
            pass

    return stats, rows


def _meta(path, rec, opts, is_link=False):
    if is_link:
        return
    if rec['perm']:
        try:
            os.chmod(path, rec['perm'])
        except OSError:
            pass
    if opts.owner and os.geteuid() == 0:
        try:
            os.chown(path, rec['uid'], rec['gid'])
        except OSError:
            pass
    if opts.times and rec['mtime']:
        try:
            os.utime(path, (rec['mtime'], rec['mtime']))
        except OSError:
            pass


# ────────────────────────────── 输出 ──────────────────────────────
def write_tree_txt(root_name, rows, path):
    lines = [root_name + '/']
    for e in sorted(rows, key=lambda x: x['path']):
        rel = e['path'].lstrip('/')
        mark = {'dir': 'd', 'ok': '-', 'link': 'l', 'recovered': 'r'}.get(e['state'], '?')
        size = f"{e['size']:>11,}" if e.get('size') else ' ' * 11
        extra = f"  -> {e['target']}" if e.get('target') else ''
        lines.append(f'{mark} {size}  {rel}{"/" if e["state"] == "dir" else ""}{extra}')
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')


def make_zip(out_dir, zip_path, rows, arcbase):
    modes = {e['path']: e.get('mode') for e in rows if e.get('mode')}
    prefix = (arcbase.strip('/') + '/') if arcbase else ''
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for dirpath, dirnames, filenames in os.walk(out_dir):
            dirnames.sort()
            rel_dir = os.path.relpath(dirpath, out_dir).replace(os.sep, '/')
            if rel_dir != '.':
                zi = zipfile.ZipInfo(prefix + rel_dir + '/')
                zi.external_attr = (0o40755 << 16) | 0x10
                z.writestr(zi, b'')
            for fn in sorted(filenames):
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, out_dir).replace(os.sep, '/')
                if os.path.islink(full):
                    # 绝不把符号链接写进 zip：解压工具/手机文件管理器可能跟随到真实存储
                    info = zipfile.ZipInfo(prefix + rel)
                    info.external_attr = (0o100644 << 16)
                    info.compress_type = zipfile.ZIP_DEFLATED
                    z.writestr(info, (LINK_NOTE % os.readlink(full)).encode('utf-8'))
                    continue
                zi = zipfile.ZipInfo.from_file(full, prefix + rel)
                zi.compress_type = zipfile.ZIP_DEFLATED
                m = modes.get('/' + rel)
                zi.external_attr = ((int(m, 8) if m else 0o644) & 0xFFFF) << 16
                with open(full, 'rb') as f:
                    z.writestr(zi, f.read())


# ────────────────────────────── 主流程 ──────────────────────────────
def human(n):
    if n is None or n < 0:
        return '?'
    for unit in ('B', 'K', 'M', 'G', 'T'):
        if n < 1024 or unit == 'T':
            return f'{n:.0f} {unit}' if unit == 'B' else f'{n:.1f} {unit}'
        n /= 1024.0


HEX_DIR_RE = re.compile(r'^[0-9a-fA-F]{8}$')


def tree_preview(root, max_depth=4, max_lines=70):
    """把展开后的目录结构压成几行文本，用来一眼看出打歪的层级"""
    lines = [os.path.basename(root.rstrip(os.sep)) + '/']
    for dirpath, dirnames, filenames in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        depth = 0 if rel == '.' else rel.count(os.sep) + 1
        ind = '  ' * (depth + 1)
        dirnames.sort()
        filenames.sort()
        if depth >= max_depth:
            dirnames[:] = []
            if filenames:
                lines.append(ind + f'… {len(filenames)} 个文件')
        else:
            for d in dirnames:
                lines.append(ind + d + '/')
            for fn in filenames:
                try:
                    sz = os.path.getsize(os.path.join(dirpath, fn))
                except OSError:
                    sz = -1
                lines.append(ind + f'{fn}  ({human(sz)})')
        if len(lines) >= max_lines:
            lines.append('  … 结构太长，已截断')
            break
    return lines


def explain_empty(bases, log):
    """0 命中时把结构、最大文件、可疑目录全打出来，省得再来回猜"""
    log('没有找到 SOMV 镜像。诊断如下：\n')
    for name, base in bases:
        log(f'── 展开后结构（{name}）──')
        for ln in tree_preview(base):
            log('  ' + ln)

        # 最大的几个文件，看前 16 字节 —— 加密/压缩/明文一眼能分出来
        big, hexdirs, fake = [], [], []
        for dp, dns, fns in os.walk(base):
            dns[:] = [d for d in dns if d not in ('__MACOSX', '.git', 'node_modules')]
            for d in dns:
                if HEX_DIR_RE.match(d):
                    hexdirs.append(os.path.join(dp, d))
            for fn in fns:
                p = os.path.join(dp, fn)
                try:
                    sz = os.path.getsize(p)
                except OSError:
                    continue
                big.append((sz, p))
                if fn.lower().endswith(('.so', '.img', '.bin')) and sz >= (8 << 10):
                    head = sniff_magic(p, 8)
                    if head[:4] != MAGIC:
                        fake.append((p, sz, head))
        big.sort(reverse=True)
        if big:
            log('\n  最大的文件：')
            for sz, p in big[:6]:
                rel = os.path.relpath(p, base)
                head = sniff_magic(p, 16)
                txt = ''.join(chr(c) if 32 <= c < 127 else '.' for c in head)
                log(f'    {human(sz):>9}  {rel:<48} 头 {head.hex(" ")}  |{txt}|')
        if fake:
            log('\n  ⚠ 看着像镜像但不是 SOMV（可能加密、或被改写过头）：')
            for p, sz, head in fake[:5]:
                log(f'    {os.path.relpath(p, base)}  {human(sz)}  头 {head.hex(" ")}')
        if hexdirs:
            log(f'\n  发现 {len(hexdirs)} 个 8 位 hex 目录（索引分片位），'
                f'但里面没有可解析的索引文件：')
            for d in hexdirs[:5]:
                ents = sorted(os.listdir(d))[:3]
                log(f'    {os.path.relpath(d, base)}/  条目样例 {ents}')

    log('\n按可能性排查：')
    log('  1. 包里只有明文文件（root/ system/ 下是普通目录和文件，没有 .so / vblock / '
        '00000000）→ 这是解包结果，不是 ROM 包；要用 vmos_pack.py 重新打成分区再塞回整包。')
    log('  2. 有 .so 但头部不是 SOMV → 镜像被加密或被别的工具改写过，'
        '先用 --probe 看上面的头部字节。')
    log('  3. 7z 提示需要密码 / 展开阶段就报错 → 加密包，vmos 这边解不了。')
    log('  4. 只有 00000000 没有镜像 → 索引在、数据没了，拿原包重打。')
    log('  5. 想让我直接看结构 → 把本屏输出整段贴出来即可（结构已经打印在上面了）。')


def probe_report(images, idx_dirs, idx_files, log):
    log(f'镜像 {len(images)} 个 / 索引目录 {len(idx_dirs)} 个 / 索引文件 {len(idx_files)} 个')
    for p in images:
        try:
            im = Image(p)
        except Exception as e:
            log(f'  ! {p}  {e}')
            continue
        kinds = {}
        for r in im.recs.values():
            k = TYPE_NAME.get(r['type'], '?')
            kinds[k] = kinds.get(k, 0) + 1
        log(f'  镜像 {p}')
        log(f'       {im.size:,} B  版本 {im.version}  inode {im.count}'
            f'（头部声明 {im.count_declared}）数据区 {im.data_size:,}')
        log(f'       记录合法率 {im.valid_ratio:.1%}  类型 {kinds}')
        im.close()
    for d in idx_dirs:
        ents = load_index_dir(d)
        n = sum(len(v) for v in ents.values())
        log(f'  索引目录 {d}  目录 {len(ents)} 个 / 条目 {n}')
    for f in idx_files:
        try:
            with open(f, 'rb') as fh:
                items = index_lines(fh.read()) or []
        except OSError:
            items = []
        log(f'  索引文件 {f}  条目 {len(items)}')


def main():
    ap = argparse.ArgumentParser(
        description='VMOS ROM 包全自动识别与还原（zip/7z/tar/目录）')
    ap.add_argument('--version', action='version',
                    version=f'vmos_auto {VERSION}  ({BUILD_NOTE})')
    ap.add_argument('inputs', nargs='+', help='压缩包或已解压目录，可多个')
    ap.add_argument('-o', '--out', default='vmos_out', help='输出根目录（默认 vmos_out）')
    ap.add_argument('--probe', action='store_true', help='只打印识别结果，不还原')
    ap.add_argument('--doctor', action='store_true',
                    help='只读诊断：检查每个镜像的记录表、数据区、重叠与越界')
    ap.add_argument('--list-only', '--tree-only', dest='list_only',
                    action='store_true', help='只列目录树，不写文件')
    ap.add_argument('--no-zip', action='store_true', help='不生成 zip')
    ap.add_argument('--no-recover', action='store_true', help='不恢复索引外的 inode')
    ap.add_argument('--links', choices=('text', 'safe', 'raw'), default='text',
                    help='链接处理：text=写占位文件(默认，最安全) / safe=仅建目录内相对链接 / raw=照原样建绝对链接(危险)')
    ap.add_argument('--no-symlink', action='store_true', help='等价于 --links text（保留兼容）')
    ap.add_argument('--no-times', action='store_true', help='不恢复 mtime')
    ap.add_argument('--owner', action='store_true', help='尝试恢复 uid/gid（需 root）')
    ap.add_argument('--json', action='store_true', help='清单输出 JSON')
    ap.add_argument('--name', help='只有一个分区时强制用这个名字')
    ap.add_argument('--keep-temp', action='store_true', help='保留解压临时目录')
    ap.add_argument('--tree', action='store_true',
                    help='只打印展开后的目录结构，不做识别（排查包结构用）')
    ap.add_argument('--tree-depth', type=int, default=4, help='--tree 的深度，默认 4')
    args = ap.parse_args()
    args.times = not args.no_times
    args.link_mode = 'text' if args.no_symlink else args.links

    def log(msg):
        print(msg, flush=True)

    out_root = os.path.abspath(args.out)
    if not args.probe and not args.list_only and not args.tree:
        os.makedirs(out_root, exist_ok=True)
    tmp_root = tempfile.mkdtemp(prefix='vmos_auto_')

    try:
        bases = []
        for raw in args.inputs:
            src = os.path.abspath(raw)
            if not os.path.exists(src):
                log(f'跳过（不存在）: {raw}')
                continue
            if os.path.isdir(src):
                bases.append((os.path.basename(src), src))
                continue
            log(f'展开 {os.path.basename(src)} ...')
            try:
                d = materialize(src, os.path.join(tmp_root, os.path.splitext(os.path.basename(src))[0]))
            except Exception as e:
                log(f'  ! {e}')
                continue
            bases.append((os.path.basename(src), d))

        if args.tree:
            for name, base in bases:
                log(f'── {name} ──')
                for ln in tree_preview(base, max_depth=max(1, args.tree_depth)):
                    log('  ' + ln)
            return

        all_images, all_dirs, all_files = [], [], []
        for _, base in bases:
            imgs, dirs, files = sniff(base, log)
            all_images += imgs
            all_dirs += dirs
            all_files += files

        log(f'\n识别：镜像 {len(all_images)}，索引目录 {len(all_dirs)}，索引文件 {len(all_files)}')
        if all_images and not all_dirs and not all_files:
            # Android 7 / 更老的 VMOS 包没有索引目录：名字存在包外，镜像记录表里
            # 只有 mode/uid/times/size/offset，没有 name、没有父 inode。
            log('  · 整包没有索引：这是 Android 7 / 老版本 VMOS 的形态，不是缺文件。'
                '\n    还原时按 inode 平铺到 _recovered/，原名和层级补不回来，'
                'ELF 用 DT_SONAME 命名，其余按内容猜扩展名。')
        if args.probe:
            probe_report(all_images, all_dirs, all_files, log)
            return
        if args.doctor:
            ims = []
            for p in all_images:
                try:
                    ims.append(Image(p))
                except Exception as e:
                    log(f'  ! {p}: {e}')
            idx = [(d, load_index_dir(d)) for d in all_dirs]
            doctor_report(ims, idx, log)
            return
        if not all_images:
            explain_empty(bases, log)
            return

        loaded = []
        for p in all_images:
            try:
                loaded.append(Image(p))
            except Exception as e:
                log(f'  ! 跳过 {p}: {e}')

        indexes = [(d, load_index_dir(d)) for d in all_dirs]
        for p in all_files:
            try:
                with open(p, 'rb') as f:
                    items = index_lines(f.read()) or []
            except OSError:
                continue
            if items:
                indexes.append((p, index_tree(items)))

        jobs = pair(loaded, indexes, log)

        pkg_has_idx = bool(all_dirs or all_files)
        summary = []
        for job in jobs:
            desc = job['desc']
            if not job['group']:
                log(f'\n⚠ 索引 {desc} 没有可用镜像（可能已被同目录其他索引占用），跳过')
                continue
            name = args.name if (args.name and len(jobs) == 1) else \
                part_name(desc, job['group'], loaded, bases[0][1])
            used_names = {s[0] for s in summary}
            if name in used_names:
                i = 2
                while f'{name}_{i}' in used_names:
                    i += 1
                name = f'{name}_{i}'

            vols = Volumes([loaded[i] for i in job['group']])
            has_idx = job['ents'] is not None
            log(f'\n=== 分区 {name} ===')
            log(f'  镜像 {vols.path}  {vols.size:,} B  inode {vols.count}'
                + (f'（{len(job["group"])} 卷合并）' if len(job["group"]) > 1 else ''))
            if has_idx:
                log(f'  索引 {desc}  目录 {len(job["ents"])} 个  覆盖 '
                    f'{len(job["covered"])}/{len(job["refs"])} 个 inode')
                shards = job.get('shards') or []
                if len(shards) > 1:
                    log(f'  索引分片 {len(shards)} 个已合并: '
                        + ', '.join(os.path.basename(x.rstrip('/')) for x in shards)
                        + (f'（同名覆盖 {job.get("conflicts", 0)} 处）'
                           if job.get('conflicts') else ''))
                if len(job['covered']) < len(job['refs']):
                    log(f'  ⚠ 有 {len(job["refs"]) - len(job["covered"])} 个 inode '
                        f'不在这些镜像里，将标记缺失')
            else:
                dirs_in_img = sum(1 for r in vols.recs.values() if r['type'] == S_IFDIR)
                if pkg_has_idx:
                    log('  ⚠ 这个分区没配上索引，按 inode 全量恢复到 _recovered/')
                else:
                    log('  · 无索引包：全部 inode 平铺到 _recovered/（这是 Android 7 老包的正常还原方式）')
                if dirs_in_img:
                    log(f'    镜像里有 {dirs_in_img} 个目录 inode，但记录表不存名字，'
                        f'目录层级补不回来；要层级就得用带索引的包')
            dest = os.path.join(out_root, name)
            if os.path.isdir(dest) and not args.list_only:
                shutil.rmtree(dest)
            stats, rows = restore(job, [loaded[i] for i in job['group']],
                                  dest, args, log)
            log(f'  目录 {stats["dir"]}  文件 {stats["file"]}  链接 {stats["link"]}  '
                f'恢复 {stats["recovered"]}  缺失 {stats["missing"]}  '
                + (f'⚠ 内容异常 {stats["suspect"]}  ' if stats['suspect'] else '')
                + (f'⚠ 尾部空 {stats["zero_tail"]}  ' if stats['zero_tail'] else '')
                + f'共 {stats["bytes"]:,} B')
            if stats['zero_tail']:
                log(f'     {stats["zero_tail"]} 个文件尾部 96 字节全 0 —— 镜像里这块可能没写数据，'
                    f'用 vmos_apex_probe.py 定位是镜像的问题还是打包的问题')

            if args.list_only:
                for e in sorted(rows, key=lambda x: x['path']):
                    log(f"    {e['path']}" + (f"  {e['size']:,}B" if e.get('size') else ''))
            else:
                write_tree_txt(name, rows, os.path.join(out_root, f'{name}_tree.txt'))
                with open(os.path.join(out_root, f'{name}_manifest.txt'), 'w',
                          encoding='utf-8') as f:
                    for e in rows:
                        ino = e.get('inode')
                        f.write(f"{e['state']:12s} {e['path']}\t{e.get('size', '')}"
                                f"\t{e.get('mode', '')}"
                                f"\t{f'{ino:08x}' if isinstance(ino, int) else ''}"
                                f"\t{'-> ' + e['target'] if e.get('target') else ''}\n")
                if args.json:
                    with open(os.path.join(out_root, f'{name}_manifest.json'), 'w',
                              encoding='utf-8') as f:
                        json.dump(rows, f, ensure_ascii=False, indent=2)
                if not args.no_zip:
                    zp = os.path.join(out_root, f'{name}_unpacked.zip')
                    make_zip(dest, zp, rows, name)
                    log(f'  打包 {zp}  {os.path.getsize(zp):,} B')
            summary.append((name, stats, has_idx))

        log('\n' + '=' * 62)
        for name, s, has_idx in summary:
            if has_idx:
                log(f'{name:14s} 目录 {s["dir"]:6d}  文件 {s["file"]:6d}  '
                    f'恢复 {s["recovered"]:5d}  缺失 {s["missing"]:5d}  {s["bytes"]:>13,} B')
            else:
                log(f'{name:14s} 无索引：平铺 {s["recovered"]:6d}  缺失 {s["missing"]:5d}'
                    f'  {s["bytes"]:>13,} B')
        log(f'输出: {out_root}')
    finally:
        for im in locals().get('loaded', []):
            try:
                im.close()
            except Exception:
                pass
        if not args.keep_temp:
            shutil.rmtree(tmp_root, ignore_errors=True)
        else:
            print(f'临时目录保留: {tmp_root}')


if __name__ == '__main__':
    main()
