#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vmos_sidecar_fix.py —— 同步 boot-sidecars.json 里的 sha256 / size

为什么需要它
------------
包根的 boot-sidecars.json 登记了 6 个文件（不是猜的，是 VMOS 自己写的）：

  root/vendor/lib64/egl/libEGL_vkhw.so
  root/vendor/lib64/egl/libGLESv1_CM_vkhw.so
  root/vendor/lib64/egl/libGLESv2_vkhw.so
  root/vendor/lib64/hw/gralloc.vkhw.so
  root/system/lib64/libvmos_memtag_off.so
  root/system/lib64/heapprofd_client_api.vmos_stub.so

启动时这几个 .so 会被 flat overlay 注入 APEX 挂载点。它们的 size 与 sha256
都写在 json 里，**改了文件却不同步 json，宿主侧的登记就对不上**。

注意：libvmoskernel.so / libvmoskernel_v2.so 里 sha256 出现 0 次，
内核本身不做哈希校验。所以「改包开不了机」默认不该先怀疑 sha256 ——
除非你动的正好是上面这 6 个文件之一。

用法
----
  # 只看差在哪（不写文件）
  python3 vmos_sidecar_fix.py rom.zip --mods out/

  # 写回 zip（其它成员一个字节不动）
  python3 vmos_sidecar_fix.py rom.zip --mods out/ -o rom_fixed.zip

  # 7z 包：只产出新 json，自己替换进去
  python3 vmos_sidecar_fix.py rom.7z --mods out/ --emit-json boot-sidecars.json
"""

import argparse
import hashlib
import json
import os
import struct
import sys
import tempfile
import zipfile

VERSION = '2026.10.31.2'
BUILD_NOTE = ('按改后的文件重算 6 个启动侧车的 sha256/size；'
              '重打包时未改成员按压缩流原样搬运')


def _big(n):
    # zipfile.ZIP64_LIMIT 是 2 GiB - 1；root/system/.so 有 2.44 GiB
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
    """成员的压缩流原样搬运：不解压不重压，2.4 GiB 的镜像只改 json 也不必重压"""
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


def human(n):
    for u in ('B', 'KB', 'MB', 'GB'):
        if n < 1024 or u == 'GB':
            return f'{n:,.0f} {u}' if u == 'B' else f'{n:.1f} {u}'
        n /= 1024.0


def sha256_of(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def find_json(root):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if not d.startswith('__MACOSX')]
        if 'boot-sidecars.json' in fns:
            return os.path.join(dp, 'boot-sidecars.json')
    return None


def resolve(mods, rel):
    """把包内相对路径映射到解包目录里的明文

    json 里是 root/vendor/lib64/...，而 vmos_auto 解出来是 out/vendor/lib64/...，
    所以先试去掉 root/ 前缀，再试原路径，最后按文件名在分区目录里找。
    """
    cands = []
    p = rel.replace('\\', '/').lstrip('/')
    if p.startswith('root/'):
        rest = p[len('root/'):]
        cands.append(os.path.join(mods, rest))
        # out/vendor/... 还是 out/system/...
        cands.append(os.path.join(mods, rest))
    cands.append(os.path.join(mods, p))
    for c in cands:
        if os.path.isfile(c):
            return c
    base = os.path.basename(p)
    for dp, dns, fns in os.walk(mods):
        dns[:] = [d for d in dns if d not in ('__MACOSX', '_recovered')]
        if base in fns:
            return os.path.join(dp, base)
    return None


def zip_replace(src_zip, member, data, out_zip, log=print):
    """替换 zip 里的一个成员，其它成员逐字节、逐顺序不动"""
    member = member.replace('\\', '/').lstrip('/')
    with zipfile.ZipFile(src_zip) as zin:
        infos = zin.infolist()
        tmp = out_zip + '.tmp'
        with zipfile.ZipFile(tmp, 'w', allowZip64=True) as zout:
            for i in infos:
                if i.filename.replace('\\', '/').lstrip('/') == member:
                    ni = zipfile.ZipInfo(member, date_time=i.date_time)
                    ni.compress_type = i.compress_type
                    ni.external_attr = i.external_attr
                    ni.create_system = i.create_system
                    zout.writestr(ni, data)
                else:
                    copy_raw(zin, zout, i)
        os.replace(tmp, out_zip)
    log(f'  已替换 {member} → {out_zip}')


def main():
    ap = argparse.ArgumentParser(
        description='按改后的文件重算 boot-sidecars.json 的 sha256/size')
    ap.add_argument('pkg', help='原包（zip / 7z / 解包目录），用于读 boot-sidecars.json')
    ap.add_argument('--mods', required=True, help='vmos_auto 解出来的目录（改完的）')
    ap.add_argument('-o', '--out', help='输出的 zip（默认在原包名前加 _fixed）')
    ap.add_argument('--emit-json', help='只把新 json 写到这个路径（7z 用这个）')
    ap.add_argument('--dry-run', action='store_true', help='只报告差异')
    ap.add_argument('--version', action='version',
                    version=f'vmos_sidecar_fix {VERSION}  ({BUILD_NOTE})')
    args = ap.parse_args()

    if not os.path.isdir(args.mods):
        raise SystemExit(f'--mods 不是目录: {args.mods}')

    # 1. 拿到 json
    tmp = None
    if os.path.isdir(args.pkg):
        js = find_json(args.pkg)
        if not js:
            raise SystemExit(f'{args.pkg} 里没有 boot-sidecars.json')
        d = json.load(open(js, encoding='utf-8'))
        member = os.path.relpath(js, args.pkg).replace(os.sep, '/')
        src_pkg = args.pkg
    else:
        import vmos_auto as va
        tmp = tempfile.mkdtemp(prefix='sidecar_')
        try:
            root = va.materialize(args.pkg, os.path.join(tmp, 'x'))
            js = find_json(root)
            if not js:
                raise SystemExit(f'{args.pkg} 里没有 boot-sidecars.json')
            d = json.load(open(js, encoding='utf-8'))
            member = os.path.relpath(js, root).replace(os.sep, '/')
            src_pkg = args.pkg
        except SystemExit:
            raise
        except Exception as e:
            raise SystemExit(f'展开 {args.pkg} 失败: {e}')

    files = d.get('files') or []
    if not files:
        raise SystemExit('boot-sidecars.json 里没有 files')

    print(f'登记 {len(files)} 个启动侧车（profile: {d.get("profile", "?")}）')
    print(f'{"路径":<50}{"登记B":>10}{"实际B":>10}  状态')
    changed = 0
    for f in files:
        rel = f.get('path', '')
        p = resolve(args.mods, rel)
        if not p:
            print(f'{rel:<50}{f.get("size", 0):>10,}{"-":>10}  ⚠ 解包目录里找不到，保持原样')
            continue
        size = os.path.getsize(p)
        sha = sha256_of(p)
        same = (size == f.get('size')) and (sha == f.get('sha256'))
        print(f'{rel:<50}{f.get("size", 0):>10,}{size:>10,}  '
              + ('✔ 一致' if same else '✘ 变了，需要更新'))
        if not same:
            changed += 1
            f['size'] = size
            f['sha256'] = sha

    if not changed:
        print('\n6 项全部一致 —— 改的不是这批文件，sha256 不是启动失败的原因。')
        return 0

    print(f'\n{changed} 项对不上。内核本身不校验 sha256（libvmoskernel*.so 里 0 处），')
    print('但宿主会按这份 json 做 flat overlay，登记对不上就会 [APEX-APP] flat overlay failed。')

    data = (json.dumps(d, ensure_ascii=False, indent=2) + '\n').encode('utf-8')

    if args.emit_json:
        with open(args.emit_json, 'wb') as f:
            f.write(data)
        print(f'\n新 json 已写到 {args.emit_json}')
        print(f'替换包里的 {member} 即可（7z 用 7z a -u 或解包后重压）')
        return 0

    if args.dry_run:
        print('\n--dry-run，没有写文件')
        return 0

    if os.path.isdir(src_pkg):
        dst = os.path.join(src_pkg, member)
        with open(dst, 'wb') as f:
            f.write(data)
        print(f'\n已更新 {dst}')
        return 0

    if not zipfile.is_zipfile(src_pkg):
        outj = args.emit_json or (os.path.splitext(os.path.basename(src_pkg))[0]
                                  + '.boot-sidecars.json')
        with open(outj, 'wb') as f:
            f.write(data)
        print(f'\n{os.path.basename(src_pkg)} 不是 zip，没法直接替换成员。')
        print(f'新 json 已写到 {outj}，请手动替换包里的 {member}')
        return 0

    out = args.out or (os.path.splitext(src_pkg)[0] + '_fixed.zip')
    zip_replace(src_pkg, member, data, out)
    print(f'输出 {out}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
