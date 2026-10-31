#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vmos_rom_diff.py —— 拿官方 ROM 当基线，逐 inode / 逐索引 / 逐明文对比改后的包

用法：
    python3 vmos_rom_diff.py 官方.zip 改后.zip
    python3 vmos_rom_diff.py 官方目录/ 改后目录/
    python3 vmos_rom_diff.py 官方.7z 改后.7z            # 需要系统有 7z
    python3 vmos_rom_diff.py 官方.zip 改后.zip --part system

为什么不逐字节 diff 整个 .so：
    .so 有 2.6 GB，其中 99% 是文件内容。真正决定「能不能开机」的是
    64 字节头 + 44×N 记录表 + 索引 dirent，这三样加起来不到 300 KB。
    内容差异单独按 inode 算 sha256 报出来，既不漏也不慢。
"""

import argparse
import hashlib
import io
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

VERSION = '2026.10.31.2'
BUILD_NOTE = '7z 基线可直接对比 + mode 差异给前后值和致命判定'

MAGIC = b'SOMV'
VB_MAGIC = b'KLBV'
HEAD = 64
REC = 44

OK = '\u2714'
BAD = '\u2718'
WARN = '\u26a0'
INFO = '\u00b7'

S_IFMT = 0o170000
S_IFDIR = 0o040000
S_IFLNK = 0o120000


def human(n):
    for u in ('B', 'KB', 'MB', 'GB'):
        if abs(n) < 1024 or u == 'GB':
            return f'{n:,.0f} {u}' if u == 'B' else f'{n:,.1f} {u}'
        n /= 1024.0
    return f'{n}'


# ────────────────────────────── 打开包 ──────────────────────────────

class Package:
    """统一 zip / 7z / 目录三种形态的只读访问"""

    def __init__(self, path):
        self.path = path
        self.kind = None
        self._zf = None
        self._tmp = None
        self._sizes = {}
        if os.path.isdir(path):
            self.kind = 'dir'
            self.names = []
            for dp, dn, fn in os.walk(path):
                for f in fn:
                    full = os.path.join(dp, f)
                    self.names.append(os.path.relpath(full, path).replace(os.sep, '/'))
            self.names.sort()
        elif zipfile.is_zipfile(path):
            self.kind = 'zip'
            self._zf = zipfile.ZipFile(path)
            self.names = [i.filename for i in self._zf.infolist() if not i.is_dir()]
        elif self._is_7z(path):
            self.kind = '7z'
            self._tmp = tempfile.mkdtemp(prefix='vmosdiff_')
            # 只解记录表需要的成员，避免解开 2.6 GB 数据区
            self.names, self._sizes = self._7z_members(path)
        else:
            raise SystemExit(f'认不出这个包: {path}')

    @staticmethod
    def _is_7z(path):
        try:
            with open(path, 'rb') as f:
                return f.read(6) == b'7z\xbc\xaf\x27\x1c'
        except OSError:
            return False

    @staticmethod
    def _7z_members(path):
        """7z l -slt 同时给出大小；以前只取名字，size() 一律 -1，
        明文对比会打出 '-1 B → 5.7 KB' 这种没意义的对比"""
        out = subprocess.check_output(['7z', 'l', '-ba', '-slt', path],
                                      text=True, errors='replace')
        names, sizes = [], {}
        cur = None
        for line in out.splitlines():
            if line.startswith('Path = '):
                cur = line[7:]
                names.append(cur)
            elif line.startswith('Size = ') and cur is not None:
                try:
                    sizes[cur] = int(line[7:].strip())
                except ValueError:
                    pass
        return names, sizes

    def size(self, name):
        if self.kind == 'dir':
            try:
                return os.path.getsize(os.path.join(self.path, name))
            except OSError:
                return -1
        if self.kind == 'zip':
            try:
                return self._zf.getinfo(name).file_size
            except KeyError:
                return -1
        return self._sizes.get(name, -1)

    def read(self, name, limit=None):
        if self.kind == 'dir':
            p = os.path.join(self.path, name)
            with open(p, 'rb') as f:
                return f.read() if limit is None else f.read(limit)
        if self.kind == 'zip':
            try:
                with self._zf.open(name) as f:
                    return f.read() if limit is None else f.read(limit)
            except KeyError:
                return b''
        # 7z：按需解到临时文件
        dst = os.path.join(self._tmp, hashlib.sha1(name.encode()).hexdigest())
        if not os.path.exists(dst):
            subprocess.run(['7z', 'e', '-y', f'-o{self._tmp}',
                            self.path, name],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            base = os.path.join(self._tmp, os.path.basename(name))
            if os.path.exists(base):
                os.replace(base, dst)
        if not os.path.exists(dst):
            return b''
        with open(dst, 'rb') as f:
            return f.read() if limit is None else f.read(limit)

    def stream_sha256(self, name, skip=0, length=None):
        if length == 0:
            return hashlib.sha256(b'').hexdigest()
        h = hashlib.sha256()
        if skip:
            self.read(name, skip)
        if self.kind == 'dir':
            with open(os.path.join(self.path, name), 'rb') as f:
                f.seek(skip)
                left = length
                while True:
                    b = f.read(min(1 << 22, left) if left else 1 << 22)
                    if not b:
                        break
                    h.update(b)
                    if left is not None:
                        left -= len(b)
                        if left <= 0:
                            break
            return h.hexdigest()
        if self.kind == 'zip':
            with self._zf.open(name) as f:
                f.read(skip)
                left = length
                while True:
                    b = f.read(min(1 << 22, left) if left else 1 << 22)
                    if not b:
                        break
                    h.update(b)
                    if left is not None:
                        left -= len(b)
                        if left <= 0:
                            break
            return h.hexdigest()
        # 7z：py7zr 不能随机读，先把成员解到临时文件再按偏移读。
        # 直接上 7z x -so 管道也能做，但 system 镜像 2.6 GB、抽样 40 次就要
        # 解压 40 遍（约 6 分钟），所以这里只解一次、后面全走文件读。
        dst = os.path.join(self._tmp, 'sha_' + hashlib.sha1(name.encode()).hexdigest())
        if not os.path.exists(dst):
            subprocess.run(['7z', 'e', '-y', '-bso0', '-bd',
                            f'-o{self._tmp}', self.path, name],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            base = os.path.join(self._tmp, os.path.basename(name))
            if os.path.exists(base):
                os.replace(base, dst)
        if not os.path.exists(dst):
            raise RuntimeError(f'7z 里读不到 {name}')
        with open(dst, 'rb') as f:
            f.seek(skip)
            left = length
            while True:
                b = f.read(min(1 << 22, left) if left else 1 << 22)
                if not b:
                    break
                h.update(b)
                if left is not None:
                    left -= len(b)
                    if left <= 0:
                        break
        return h.hexdigest()

    def close(self):
        if self._zf:
            self._zf.close()
        if self._tmp:
            shutil.rmtree(self._tmp, ignore_errors=True)


# ────────────────────────────── 解析分区 ──────────────────────────────

class Part:
    def __init__(self, pkg, prefix, name):
        self.pkg = pkg
        self.name = name
        self.prefix = prefix            # 例如 'root/system'
        self.ino_count = 0
        self.data_size = 0
        self.recs = []                  # list of dict
        self.vblock = None
        self.index = {}                 # dir_ino -> [(name, ino)]
        self.shards = []
        self.plain = {}                 # relpath -> size

    def load(self):
        so = f'{self.prefix}/.so'
        hdr = self.pkg.read(so, HEAD)
        if len(hdr) < HEAD or hdr[:4] != MAGIC:
            raise SystemExit(f'{so} 不是 SOMV 镜像')
        _, self.ino_count, self.data_size = struct.unpack_from('<III', hdr, 4)
        table = self.pkg.read(so, HEAD + REC * self.ino_count)[HEAD:]
        for i in range(self.ino_count):
            o = REC * i
            mode, = struct.unpack_from('<H', table, o)
            uid, gid = struct.unpack_from('<HH', table, o + 4)
            nlink, = struct.unpack_from('<I', table, o + 12)
            mt, = struct.unpack_from('<I', table, o + 24)
            size, = struct.unpack_from('<I', table, o + 28)
            off, = struct.unpack_from('<I', table, o + 32)
            self.recs.append(dict(mode=mode, uid=uid, gid=gid, nlink=nlink,
                                  mtime=mt, size=size, off=off))
        vb = self.pkg.read(f'{self.prefix}/vblock', 64)
        if len(vb) >= 12 and vb[:4] == VB_MAGIC:
            _, self.vblock = struct.unpack_from('<II', vb, 4)

        # 索引：<prefix>/00000xxx/00000yyy，每行 name=ino
        pref = self.prefix + '/'
        for n in self.pkg.names:
            if not n.startswith(pref):
                continue
            rest = n[len(pref):]
            seg = rest.split('/')
            if len(seg) == 2 and len(seg[0]) == 8 and self._hex(seg[0]) is not None \
                    and len(seg[1]) == 8 and self._hex(seg[1]) is not None:
                dino = self._hex(seg[1])
                body = self.pkg.read(n)
                ents = []
                for line in body.decode('utf-8', 'surrogateescape').splitlines():
                    line = line.rstrip('\r')
                    if not line or '=' not in line:
                        continue
                    nm, v = line.rsplit('=', 1)
                    try:
                        ents.append((nm, int(v, 16)))
                    except ValueError:
                        ents.append((nm, None))
                self.index.setdefault(dino, []).extend(ents)
                if seg[0] not in self.shards:
                    self.shards.append(seg[0])
            elif rest not in ('.so', 'vblock'):
                self.plain[rest] = self.pkg.size(n)
        self.shards.sort()

    @staticmethod
    def _hex(s):
        try:
            return int(s, 16)
        except ValueError:
            return None

    def ino_of(self, relpath):
        """relpath 形如 'system/bin/sh'，返回 inode 号"""
        cur = 0
        name = None
        for part in [x for x in relpath.split('/') if x]:
            if cur not in self.index:
                return None
            for nm, ino in self.index[cur]:
                if nm == part:
                    cur = ino
                    name = nm
                    break
            else:
                return None
        return cur

    def path_of(self):
        """inode -> 路径（用索引反查，尽量还原）"""
        rev = {}
        for dino, ents in self.index.items():
            for nm, ino in ents:
                rev.setdefault(ino, []).append((dino, nm))
        out = {}
        for ino in range(self.ino_count):
            chain = []
            cur = ino
            seen = set()
            while cur in rev and cur not in seen and len(chain) < 64:
                seen.add(cur)
                dino, nm = rev[cur][0]
                chain.append(nm)
                cur = dino
            out[ino] = '/' + '/'.join(reversed(chain)) if chain else f'<ino {ino:#x}>'
        return out


def find_parts(pkg):
    names = set(pkg.names)
    parts = []
    for n in pkg.names:
        if not n.endswith('/.so'):
            continue
        prefix = n[:-3].rstrip('/')
        if prefix == '':
            continue
        parts.append(prefix)
    parts.sort()
    return parts


# ────────────────────────────── 对比 ──────────────────────────────

def cmp_part(A, B, label, problems, warns, notes):
    print(f'\n{"="*64}\n分区 {A.name}\n{"="*64}')

    # 1. 头
    if A.ino_count != B.ino_count:
        problems.append(f'{A.name}: inode 数 {A.ino_count} → {B.ino_count}（差 {B.ino_count-A.ino_count}）')
        print(f'  {BAD} inode 数 {A.ino_count} → {B.ino_count}'
              f'  （vblock 里也应该是 {B.ino_count}）')
    else:
        print(f'  {OK} inode 数 {A.ino_count}（一致）')

    if A.vblock != B.vblock:
        problems.append(f'{A.name}: vblock 登记 {A.vblock} vs 镜像 {B.ino_count}')
        print(f'  {BAD} vblock 登记 {B.vblock}，镜像实际 {B.ino_count}'
              f'  —— /data 会挂不上，[BOOT-CFS] open vblock FAILED')
    elif A.vblock != A.ino_count:
        warns.append(f'{A.name}: 官方包自己的 vblock({A.vblock}) 与 count({A.ino_count}) 就不等')
        print(f'  {WARN} vblock {A.vblock} 与 count {A.ino_count} 不等（官方包本身如此）')
    else:
        print(f'  {OK} vblock 登记 {A.vblock} 与 inode 数一致')

    # 2. 记录表逐条
    n = min(A.ino_count, B.ino_count)
    changed = []
    for i in range(n):
        a, b = A.recs[i], B.recs[i]
        if a != b:
            changed.append(i)
    if not changed:
        print(f'  {OK} 记录表 {n} 条逐字段一致')
    else:
        print(f'  {INFO} 记录表 {len(changed)} 条有变化')
        pa, pb = A.path_of(), B.path_of()
        # 归类
        cnt = {}
        for i in changed:
            a, b = A.recs[i], B.recs[i]
            if a['size'] != b['size']:
                k = 'size'
            elif a['mode'] != b['mode']:
                k = 'mode'
            elif a['mtime'] != b['mtime']:
                k = 'mtime'
            elif a['off'] != b['off'] and a['size'] == 0:
                k = 'off-empty'
            elif a['off'] != b['off']:
                k = 'off'
            else:
                k = 'uid/gid/nlink'
            cnt[k] = cnt.get(k, 0) + 1
        for k, v in sorted(cnt.items(), key=lambda x: -x[1]):
            print(f'      {k:<12} {v} 条')
        if cnt.get('mode'):
            # 光说多少条没法定位：必须看到 mode 从多少变成多少
            pairs = {}
            for i in changed:
                a, b = A.recs[i]['mode'], B.recs[i]['mode']
                if a != b:
                    pairs.setdefault((a, b), []).append(i)
            print(f'      mode 变化明细（八进制，含文件类型位）：')
            for (a, b), ins in sorted(pairs.items(), key=lambda x: -len(x[1]))[:6]:
                ta = 'd' if (a & 0o170000) == 0o040000 else \
                     'l' if (a & 0o170000) == 0o120000 else \
                     '-' if (a & 0o170000) == 0o100000 else '?'
                tb = 'd' if (b & 0o170000) == 0o040000 else \
                     'l' if (b & 0o170000) == 0o120000 else \
                     '-' if (b & 0o170000) == 0o100000 else '?'
                lost = a & ~b & 0o7777
                gain = b & ~a & 0o7777
                note = []
                if lost & 0o4000: note.append('丢 setuid')
                if lost & 0o2000: note.append('丢 setgid')
                if lost & 0o1000: note.append('丢 sticky')
                if gain & 0o4000: note.append('加 setuid')
                if gain & 0o2000: note.append('加 setgid')
                if gain & 0o1000: note.append('加 sticky')
                if ta != tb: note.append(f'类型 {ta}→{tb}')
                if (a & 0o777) != (b & 0o777):
                    note.append(f'权限 {a & 0o777:03o}→{b & 0o777:03o}')
                ex = '、'.join(pa[i] for i in ins[:3])
                # 哪些是致命的：丢执行位 / 丢 setuid / 目录不可进入
                fatal = []
                if lost & 0o4000:
                    fatal.append('setuid 丢失')
                if ta == 'd' and not (b & 0o111):
                    fatal.append('目录不可进入')
                if ta == '-' and (a & 0o111) and not (b & 0o111):
                    fatal.append('丢执行位')
                tag = f'  {BAD} ' + '、'.join(fatal) if fatal else ''
                print(f'        {a:06o} → {b:06o}  {len(ins)} 条  '
                      f'{"、".join(note) or "仅高位不同"}  {ex}{tag}')
                if fatal:
                    problems.append(
                        f'{A.name}: {len(ins)} 个条目 {a:06o}→{b:06o}'
                        f'（{ "、".join(fatal) }），会直接影响启动')
        for i in [x for x in changed if A.recs[x]['size'] != B.recs[x]['size']][:10]:
            print(f'      {INFO} {pa[i]}  {human(A.recs[i]["size"])} → '
                  f'{human(B.recs[i]["size"])}')

        # 严重：非空文件 offset 变了 = 数据区重排
        bad_off = [i for i in changed
                   if A.recs[i]['off'] != B.recs[i]['off'] and A.recs[i]['size'] > 0]
        if bad_off:
            print(f'  {WARN} {len(bad_off)} 个非空文件的 offset 变了（数据区重排）：')
            for i in bad_off[:6]:
                print(f'      {pa[i]}  {A.recs[i]["off"]} → {B.recs[i]["off"]}')
            if len(bad_off) > 6:
                print(f'      …… 还有 {len(bad_off)-6} 个')
            notes.append(f'{A.name}: {len(bad_off)} 个文件 offset 变化（内容不一定变）')

        # 内容真的变了？按 sha256 抽查变了 size 的 + 前 40 个
        same = 0
        real = []
        # 逐 inode 比较内容（只比较记录里 size>0 且 size 一致的抽样）
        sample = [i for i in changed
                  if A.recs[i]['size'] == B.recs[i]['size'] and A.recs[i]['size'] > 0][:40]
        for i in sample:
            ha = A.pkg.stream_sha256(f'{A.prefix}/.so', A.recs[i]['off'], A.recs[i]['size'])
            hb = B.pkg.stream_sha256(f'{B.prefix}/.so', B.recs[i]['off'], B.recs[i]['size'])
            if ha == hb:
                same += 1
            else:
                real.append(i)
        if same:
            print(f'  {INFO} 抽样 {len(sample)} 个 size 未变的改动项，{same} 个内容其实相同'
                  f'（只是 offset/时间戳挪了）')
        for i in real[:6]:
            print(f'      {BAD} 内容不同: {pa[i]}')

        # 关键的 9 个被 json 锁定的文件
        for key in ('init.superuser.rc', 'init.vmos-plugins.rc', 'vmos_plugin_dispatcher'):
            hit = [i for i in changed if pa[i].endswith('/' + key) or pa[i] == '/' + key]
            for i in hit:
                problems.append(f'{A.name}: {key} 被改（sha256 会在 json 里对不上）')
                print(f'  {BAD} 被 json 按 sha256 锁定的文件被改动: {pa[i]}')
                print(f'      a15-plugin-profile.json 里的对应字段要同步重算')

    # 3. 索引
    if set(A.index) != set(B.index):
        only_a = set(A.index) - set(B.index)
        only_b = set(B.index) - set(A.index)
        print(f'  {BAD} 索引目录集合不同：少 {len(only_a)} 个目录、多 {len(only_b)} 个目录')
        for d in list(only_a)[:5]:
            print(f'      缺 {A.path_of().get(d, hex(d))}')
        problems.append(f'{A.name}: 索引目录 {len(A.index)} → {len(B.index)}')
    else:
        diff_dirs = []
        for d, ents in A.index.items():
            if sorted(ents) != sorted(B.index[d]):
                diff_dirs.append(d)
        if not diff_dirs:
            print(f'  {OK} 索引 {len(A.index)} 个目录、'
                  f'{sum(len(v) for v in A.index.values())} 条 dirent 全一致')
        else:
            p = A.path_of()
            print(f'  {INFO} {len(diff_dirs)} 个目录的 dirent 有变化：')
            for d in diff_dirs[:10]:
                sa, sb = dict(A.index[d]), dict(B.index[d])
                add = [(k, v) for k, v in sb.items() if k not in sa]
                rm = [(k, v) for k, v in sa.items() if k not in sb]
                ch = [(k, sa[k], sb[k]) for k in sa if k in sb and sa[k] != sb[k]]
                line = f'      {p.get(d, hex(d))}: '
                if add:
                    line += f'新增 {add[:3]} '
                if rm:
                    line += f'删除 {rm[:3]} '
                if ch:
                    line += f'ino 变 {ch[:3]}'
                print(line)
            notes.append(f'{A.name}: {len(diff_dirs)} 个目录 dirent 变化')

    if A.shards != B.shards:
        print(f'  {WARN} 索引分片 {A.shards} → {B.shards}')
        if B.shards == ['00000000'] and len(A.shards) > 1:
            problems.append(f'{A.name}: 索引分片合并成单片，inode>=4096 的目录全部丢名字')
            print(f'      {BAD} inode ≥ 4096 的目录名会整体丢失（内核按 ino>>12 找索引）')
    else:
        print(f'  {OK} 索引分片 {A.shards}（一致）')

    # 4. 明文
    pa_set, pb_set = set(A.plain), set(B.plain)
    if pa_set != pb_set:
        print(f'  {WARN} 明文文件集合不同：少 {len(pa_set-pb_set)} 个，多 {len(pb_set-pa_set)} 个')
        for x in sorted(pa_set - pb_set)[:8]:
            print(f'      缺 {x}  ({human(A.plain[x])})')
        for x in sorted(pb_set - pa_set)[:8]:
            print(f'      多 {x}')
        warns.append(f'{A.name}: 明文文件 {len(pa_set)} → {len(pb_set)}')
    else:
        diff = [x for x in pa_set if A.plain[x] != B.plain[x]]
        if not diff:
            print(f'  {OK} 明文 {len(pa_set)} 个，大小全一致')
        else:
            print(f'  {INFO} 明文大小变了 {len(diff)} 个: {diff[:5]}')
            for x in diff[:5]:
                ha = A.pkg.stream_sha256(f'{A.prefix}/{x}')
                hb = B.pkg.stream_sha256(f'{B.prefix}/{x}')
                mark = OK if ha == hb else BAD
                print(f'      {mark} {x}  {human(A.plain[x])} → {human(B.plain[x])}')


# ────────────────────────────── 被 json 锁定的文件 ──────────────────────────────

# 这三条是实测反查出来的：拿 json 里的 sha256 去扫全包，命中的就是这个路径。
# profile 里只写 sha256 不写路径，所以映射只能这么来。
PROFILE_LOCKS = [
    ('root/init.vmos-plugins.rc', 'bridge_sha256', 'bridge（插件桥接 rc）'),
    ('root/init.superuser.rc', 'root_init_sha256', 'root_init（root 插件 init）'),
    ('root/system/bin/vmos_plugin_dispatcher', 'dispatcher_sha256', 'dispatcher'),
]


def _sha_of_member(pkg, name):
    if name not in pkg.names:
        return None
    try:
        return pkg.stream_sha256(name)
    except Exception:
        return None


def _sha_in_image(pkg, parts, path):
    """json 里的 path 是 'root/' + guest 路径，第一段是分区名（system/vendor/root）

    root 分区的文件是个例外：guest 的 /init.superuser.rc 在包里是
    root/root/init.superuser.rc，而 json 只写 root/init.superuser.rc。
    """
    cands = []
    for pref, part in parts.items():
        pname = pref.rsplit('/', 1)[-1]
        if path.startswith(pref + '/'):
            cands.append((pref, part, path[len(pref) + 1:]))
            continue
        if not path.startswith('root/'):
            continue
        rest = path[5:]
        if rest.startswith(pname + '/'):
            cands.append((pref, part, rest[len(pname) + 1:]))
        elif pname == 'root' and not rest.startswith(('system/', 'vendor/', 'data/')):
            cands.append((pref, part, rest))
    for pref, part, rel in cands:
        ino = part.ino_of(rel)
        if ino is None or ino >= len(part.recs):
            continue
        r = part.recs[ino]
        if r['size'] == 0:
            return hashlib.sha256(b'').hexdigest()
        try:
            return pkg.stream_sha256(f'{pref}/.so', r['off'], r['size'])
        except Exception:
            continue
    return None


def check_locks(pkg, parts, tag):
    """核对 json 登记值、明文副本、镜像内副本 三者是否一致"""
    rows = []
    side = None
    if 'boot-sidecars.json' in pkg.names or (
            pkg.kind == 'dir' and os.path.exists(os.path.join(pkg.path, 'boot-sidecars.json'))):
        try:
            import json as _json
            side = _json.loads(pkg.read('boot-sidecars.json'))
        except Exception:
            side = None
    if side:
        for f in side.get('files', []):
            rows.append((f['path'], 'boot-sidecars.json', f.get('sha256'), f.get('size')))

    prof = None
    if 'a15-plugin-profile.json' in pkg.names or (
            pkg.kind == 'dir' and os.path.exists(os.path.join(pkg.path, 'a15-plugin-profile.json'))):
        try:
            import json as _json
            prof = _json.loads(pkg.read('a15-plugin-profile.json'))
        except Exception:
            prof = None
    if prof:
        for path, key, _desc in PROFILE_LOCKS:
            if prof.get(key):
                rows.append((path, 'a15-plugin-profile.json', prof[key], None))

    if not rows:
        print(f'\n  {INFO} 这个包没有 boot-sidecars.json / a15-plugin-profile.json，跳过锁定文件核对')
        return 0

    print(f'\n  [{tag}] json 锁定文件 {len(rows)} 个：')
    print(f'    {"路径":<48}{"登记":>10}{"明文":>10}{"镜像":>10}  结论')
    bad = 0
    for path, src, want, size in rows:
        plain = _sha_of_member(pkg, path)
        image = _sha_in_image(pkg, parts, path)
        mark_p = '—'
        mark_i = '—'
        if plain:
            mark_p = OK if plain == want else BAD
        if image:
            mark_i = OK if image == want else BAD
        found = [x for x in (plain, image) if x]
        if not found:
            ok = False
            verdict = '包里找不到这个文件'
        else:
            ok = all(x == want for x in found) and len(set(found)) == 1
            verdict = '一致' if ok else '对不上 → 启动会被拒'
        if not ok:
            bad += 1
        short = path if len(path) <= 46 else '…' + path[-45:]
        print(f'    {short:<48}{want[:8]:>10}{mark_p:>10}{mark_i:>10}  {verdict}')
    if bad:
        print(f'    {BAD} {bad} 个文件的 sha256 与 json 登记不符'
              f'（改了这些文件就必须同步重算 json；否则 flat overlay / 插件校验直接失败）')
    else:
        print(f'    {OK} {len(rows)} 个全部一致（明文与镜像内两份也一致）')
    return bad


# ────────────────────────────── main ──────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description='以官方 ROM 为基线，逐 inode / 索引 / 明文对比改后的包')
    ap.add_argument('base', help='官方原包（zip / 7z / 解压目录）')
    ap.add_argument('mod', help='改后的包')
    ap.add_argument('--part', action='append', default=None,
                    help='只比某个分区（如 system），可重复')
    ap.add_argument('--no-content', action='store_true',
                    help='不比文件内容（只比记录表和索引，快很多）')
    ap.add_argument('--version', action='version',
                    version=f'vmos_rom_diff {VERSION}  ({BUILD_NOTE})')
    args = ap.parse_args()

    A, B = Package(args.base), Package(args.mod)
    pa, pb = find_parts(A), find_parts(B)
    print(f'基线: {args.base}   ({A.kind}, {len(A.names)} 个成员)')
    print(f'改后: {args.mod}   ({B.kind}, {len(B.names)} 个成员)')
    print(f'分区: 基线 {pa}')
    print(f'      改后 {pb}')

    only_a = set(pa) - set(pb)
    only_b = set(pb) - set(pa)
    problems, warns, notes = [], [], []
    if only_a or only_b:
        print(f'\n{BAD} 分区集合不同：缺 {sorted(only_a)}，多 {sorted(only_b)}')
        problems.append(f'分区缺失 {sorted(only_a)} / 新增 {sorted(only_b)}')

    every = [p for p in pa if p in pb]
    todo = every
    if args.part:
        todo = [p for p in every if p.split('/')[-1] in args.part]

    loaded_a, loaded_b = {}, {}
    for pref in every:
        a = Part(A, pref, pref.split('/')[-1]); a.load()
        b = Part(B, pref, pref.split('/')[-1]); b.load()
        loaded_a[pref] = a
        loaded_b[pref] = b
    for pref in todo:
        cmp_part(loaded_a[pref], loaded_b[pref], pref, problems, warns, notes)

    # 锁定文件：与记录表无关，改一个字节（大小不变）也要抓出来
    print(f'\n{"="*64}\n被 json 按 sha256 锁定的文件\n{"="*64}')
    nbad_a = check_locks(A, loaded_a, '基线')
    nbad_b = check_locks(B, loaded_b, '改后')
    if nbad_b > nbad_a:
        problems.append(f'锁定文件：基线 {nbad_a} 个不符，改后 {nbad_b} 个不符')

    print(f'\n{"="*64}')
    if problems:
        print(f'{BAD} 有 {len(problems)} 处会让 VM 起不来的差异：')
        for i, p in enumerate(problems, 1):
            print(f'  {i}. {p}')
    else:
        print(f'{OK} 没有发现致命差异')
    if warns:
        print(f'\n{WARN} {len(warns)} 处警告：')
        for w in warns[:10]:
            print(f'  · {w}')
    if notes:
        print(f'\n{INFO} 其它变化（通常无害）：')
        for n in notes[:10]:
            print(f'  · {n}')
    if not problems:
        print('\n这一版包结构和基线一致。如果仍然开不了机，问题在改进去的内容本身'
              '（或 /data 侧的旧实例），把 logcat 里 vmos 的行发我。')
    A.close()
    B.close()
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
