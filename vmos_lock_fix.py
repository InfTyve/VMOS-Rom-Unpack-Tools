#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vmos_lock_fix.py —— 改过 ROM 里被 json 按 sha256 锁定的文件后，把登记值同步回去

VMOS 的 A15 ROM 根目录有两份清单，一共锁了 9 个文件：

    boot-sidecars.json         6 个（vendor 的 egl / gralloc、system 的 2 个 vmos stub）
    a15-plugin-profile.json    3 个（root/init.vmos-plugins.rc、root/init.superuser.rc、
                                    system/bin/vmos_plugin_dispatcher）

这 9 个文件里任何一个内容变了、json 里的 sha256 还是旧的，启动就会被拒：
sidecars 是 [APEX-APP] flat overlay failed，profile 是插件链校验失败。

用法：
    # 1. 只看差在哪（不改任何文件）
    python3 vmos_lock_fix.py rom.zip --mods out/

    # 2. 目录形态的包：直接改 json
    python3 vmos_lock_fix.py rom_dir/ --mods out/ --write

    # 3. zip / 7z：把新 json 吐出来，自己塞回去
    python3 vmos_lock_fix.py rom.zip --mods out/ --emit-json ./fixed/

    # 4. 只算文件自己的 sha256（排查用）
    python3 vmos_lock_fix.py rom.zip --show
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
BUILD_NOTE = ('同步 boot-sidecars.json / a15-plugin-profile.json 里的 sha256；'
              '重打包时未改成员按压缩流原样搬运')

HEAD = 64
REC = 44
MAGIC = b'SOMV'

# profile 只写 sha256 不写路径；这三条是拿 sha256 反查全包实测出来的
PROFILE_LOCKS = [
    ('root/init.vmos-plugins.rc', 'bridge_sha256'),
    ('root/init.superuser.rc', 'root_init_sha256'),
    ('root/system/bin/vmos_plugin_dispatcher', 'dispatcher_sha256'),
]

OK = '\u2714'
BAD = '\u2718'
WARN = '\u26a0'
INFO = '\u00b7'


def human(n):
    for u in ('B', 'KB', 'MB', 'GB'):
        if abs(n) < 1024 or u == 'GB':
            return f'{n:,.0f} {u}' if u == 'B' else f'{n:,.1f} {u}'
        n /= 1024.0


def _big(n):
    # zipfile.ZIP64_LIMIT 是 2 GiB - 1；system/.so 有 2.44 GiB
    return n > zipfile.ZIP64_LIMIT


def _strip_zip64(extra):
    """剥掉 extra 里的 zip64(0x0001) 段，避免和新写的 zip64 段重复"""
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


def copy_raw(zin, zout, info):
    """成员的压缩流原样搬运：不解压、不重压，几个 GB 也是纯拷贝"""
    zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
    zi.compress_type = info.compress_type
    zi.external_attr = info.external_attr
    zi.internal_attr = info.internal_attr
    zi.create_system = info.create_system
    zi.comment = info.comment
    zi.extra = _strip_zip64(info.extra)
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


class Src:
    """包：zip 或目录"""

    def __init__(self, path):
        self.path = path
        self.disk = os.path.isdir(path)
        self.zf = None
        if self.disk:
            self.names = []
            for dp, _dn, fn in os.walk(path):
                for f in fn:
                    self.names.append(
                        os.path.relpath(os.path.join(dp, f), path).replace(os.sep, '/'))
            self.names.sort()
        elif zipfile.is_zipfile(path):
            self.zf = zipfile.ZipFile(path)
            self.names = [i.filename for i in self.zf.infolist() if not i.is_dir()]
        else:
            raise SystemExit(f'{path} 既不是目录也不是 zip（7z 请先解开）')

    def has(self, name):
        if self.disk:
            return os.path.isfile(os.path.join(self.path, name))
        try:
            self.zf.getinfo(name)
            return True
        except KeyError:
            return False

    def read(self, name, limit=None):
        if self.disk:
            with open(os.path.join(self.path, name), 'rb') as f:
                return f.read() if limit is None else f.read(limit)
        with self.zf.open(name) as f:
            return f.read() if limit is None else f.read(limit)

    def sha(self, name):
        h = hashlib.sha256()
        if self.disk:
            with open(os.path.join(self.path, name), 'rb') as f:
                for b in iter(lambda: f.read(1 << 22), b''):
                    h.update(b)
        else:
            with self.zf.open(name) as f:
                for b in iter(lambda: f.read(1 << 22), b''):
                    h.update(b)
        return h.hexdigest()


class Image:
    """一个分区的 SOMV 镜像（只读索引 + 记录表）"""

    def __init__(self, src, prefix):
        self.src = src
        self.prefix = prefix
        hdr = src.read(prefix + '/.so', HEAD)
        if hdr[:4] != MAGIC:
            raise ValueError(prefix)
        _, self.count, self.dsize = struct.unpack_from('<III', hdr, 4)
        T = src.read(prefix + '/.so', HEAD + REC * self.count)[HEAD:]
        self.recs = []
        for i in range(self.count):
            o = REC * i
            size, = struct.unpack_from('<I', T, o + 28)
            off, = struct.unpack_from('<I', T, o + 32)
            self.recs.append((size, off))
        self.index = {}
        pref = prefix + '/'
        for n in src.names:
            if not n.startswith(pref):
                continue
            seg = n[len(pref):].split('/')
            if len(seg) == 2 and len(seg[0]) == 8 and len(seg[1]) == 8:
                try:
                    dino = int(seg[1], 16)
                except ValueError:
                    continue
                body = src.read(n).decode('utf-8', 'surrogateescape')
                for line in body.splitlines():
                    line = line.rstrip('\r')
                    if '=' not in line:
                        continue
                    nm, v = line.rsplit('=', 1)
                    try:
                        self.index.setdefault(dino, {})[nm] = int(v, 16)
                    except ValueError:
                        pass

    def ino_of(self, rel):
        cur = 0
        for part in [x for x in rel.split('/') if x]:
            nxt = self.index.get(cur, {}).get(part)
            if nxt is None:
                return None
            cur = nxt
        return cur

    def sha_of(self, rel):
        ino = self.ino_of(rel)
        if ino is None or ino >= len(self.recs):
            return None
        size, off = self.recs[ino]
        if size == 0:
            return hashlib.sha256(b'').hexdigest(), 0
        h = hashlib.sha256()
        if self.src.disk:
            with open(os.path.join(self.src.path, self.prefix, '.so'), 'rb') as f:
                f.seek(off)
                left = size
                while left > 0:
                    b = f.read(min(1 << 22, left))
                    if not b:
                        break
                    h.update(b)
                    left -= len(b)
        else:
            with self.src.zf.open(self.prefix + '/.so') as f:
                f.seek(off)
                left = size
                while left > 0:
                    b = f.read(min(1 << 22, left))
                    if not b:
                        break
                    h.update(b)
                    left -= len(b)
        return h.hexdigest(), size


def find_images(src):
    out = {}
    for n in src.names:
        if n.endswith('/.so'):
            pref = n[:-3].rstrip('/')
            try:
                out[pref] = Image(src, pref)
            except Exception:
                pass
    return out


def resolve(src, images, path, mods):
    """返回 (sha256, size, 来源)。mods > 明文 > 镜像"""
    if mods:
        for cand in (os.path.join(mods, path),
                     os.path.join(mods, path[len('root/'):])
                     if path.startswith('root/') else None):
            if cand and os.path.isfile(cand):
                h = hashlib.sha256()
                with open(cand, 'rb') as f:
                    for b in iter(lambda: f.read(1 << 22), b''):
                        h.update(b)
                return h.hexdigest(), os.path.getsize(cand), '解包目录'
    if src.has(path):
        return src.sha(path), len(src.read(path, 1)), '明文'
    for pref, img in images.items():
        pname = pref.rsplit('/', 1)[-1]
        rel = None
        if path.startswith(pref + '/'):
            rel = path[len(pref) + 1:]
        elif path.startswith('root/'):
            rest = path[5:]
            if rest.startswith(pname + '/'):
                rel = rest[len(pname) + 1:]
            elif pname == 'root' and not rest.startswith(('system/', 'vendor/', 'data/')):
                rel = rest
        if rel is None:
            continue
        got = img.sha_of(rel)
        if got:
            return got[0], got[1], '镜像'
    return None, None, None


def main():
    ap = argparse.ArgumentParser(
        description='同步 ROM 里被 json 按 sha256 锁定的 9 个文件的登记值')
    ap.add_argument('pkg', help='ROM 包（zip 或解压目录；7z 请先解开）')
    ap.add_argument('--mods', help='解包后改过文件的目录（优先用它算 sha256）')
    ap.add_argument('--write', action='store_true',
                    help='目录形态的包直接改 json；zip 会重打包（慢）')
    ap.add_argument('--emit-json', metavar='DIR',
                    help='把新的 json 写到这个目录，不动原包')
    ap.add_argument('--show', action='store_true', help='只打印实际 sha256，便于排查')
    ap.add_argument('--version', action='version',
                    version=f'vmos_lock_fix {VERSION}  ({BUILD_NOTE})')
    args = ap.parse_args()

    src = Src(args.pkg)
    images = find_images(src)
    print(f'包: {args.pkg}  ({len(src.names)} 个成员, {len(images)} 个分区)')
    if args.mods:
        print(f'改动目录: {args.mods}')

    plan = []   # (json 名, 字段定位, path, 登记sha, 实际sha, 实际size, 来源)

    side_name = 'boot-sidecars.json'
    side = None
    if src.has(side_name):
        try:
            side = json.loads(src.read(side_name))
        except Exception as e:
            print(f'{BAD} {side_name} 解析失败: {e}')
    prof_name = 'a15-plugin-profile.json'
    prof = None
    if src.has(prof_name):
        try:
            prof = json.loads(src.read(prof_name))
        except Exception as e:
            print(f'{BAD} {prof_name} 解析失败: {e}')

    if side:
        for i, f in enumerate(side.get('files', [])):
            plan.append((side_name, ('files', i), f.get('path'), f.get('sha256'),
                         f.get('size')))
    if prof:
        for path, key in PROFILE_LOCKS:
            if prof.get(key):
                plan.append((prof_name, ('key', key), path, prof[key], None))

    if not plan:
        print(f'{WARN} 包里没有这两份清单，没什么可同步的')
        return 1

    print(f'\n{"路径":<50}{"登记":>10}{"实际":>10}  来源      结论')
    changed = []
    for jname, loc, path, want, wsize in plan:
        got, size, where = resolve(src, images, path, args.mods)
        if got is None:
            print(f'{path:<50}{str(want)[:8]:>10}{"找不到":>10}  {"-":<9} {BAD} 包里没有这个文件')
            continue
        same = got == want
        short = path if len(path) <= 48 else '…' + path[-47:]
        print(f'{short:<50}{str(want)[:8]:>10}{got[:8]:>10}  {where:<9} '
              f'{OK + " 一致" if same else BAD + " 需要更新"}')
        if not same:
            changed.append((jname, loc, path, got, size))

    if args.show:
        print()
        for jname, loc, path, got, size in changed:
            print(f'  {path}\n    sha256 = {got}\n    size   = {size:,}')
        return 0

    if not changed:
        print(f'\n{OK} 9 项全部一致，json 不用动。')
        return 0

    print(f'\n{INFO} {len(changed)} 项需要更新')
    # 应用到 json 对象
    for jname, loc, path, got, size in changed:
        obj = side if jname == side_name else prof
        if loc[0] == 'files':
            ent = obj['files'][loc[1]]
            ent['sha256'] = got
            if ent.get('size') is not None and size is not None:
                ent['size'] = size
        else:
            obj[loc[1]] = got

    if args.emit_json:
        os.makedirs(args.emit_json, exist_ok=True)
        for jname, obj in ((side_name, side), (prof_name, prof)):
            if not obj:
                continue
            dst = os.path.join(args.emit_json, jname)
            with open(dst, 'w', encoding='utf-8') as f:
                json.dump(obj, f, ensure_ascii=False, indent=2)
                f.write('\n')
            print(f'  写出 {dst}')
        print(f'\n{INFO} 把这两个文件替换回包里即可（7z 包只能这么办）。')
        return 0

    if not args.write:
        print(f'\n{INFO} 加 --write 直接改包；zip 包会重打包；或用 --emit-json 只吐 json。')
        return 0

    if src.disk:
        for jname, obj in ((side_name, side), (prof_name, prof)):
            if not obj:
                continue
            dst = os.path.join(src.path, jname)
            with open(dst, 'w', encoding='utf-8') as f:
                json.dump(obj, f, ensure_ascii=False, indent=2)
                f.write('\n')
            print(f'  {OK} 已更新 {dst}')
        return 0

    # zip：重建（未改成员按压缩流原样搬运，2.4 GiB 的镜像不必重压）
    tmp = args.pkg + '.lockfix.tmp'
    with zipfile.ZipFile(args.pkg) as zin, \
            zipfile.ZipFile(tmp, 'w', zipfile.ZIP_STORED, allowZip64=True) as zout:
        for info in zin.infolist():
            if info.filename in (side_name, prof_name):
                obj = side if info.filename == side_name else prof
                if not obj:
                    data = zin.read(info)
                else:
                    data = (json.dumps(obj, ensure_ascii=False, indent=2) + '\n').encode()
                zout.writestr(info, data)
            else:
                copy_raw(zin, zout, info)
    os.replace(tmp, args.pkg)
    print(f'  {OK} 已重打包 {args.pkg}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
