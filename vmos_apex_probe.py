#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vmos_apex_probe.py —— APEX 数据到底在哪：从镜像直接读，不走解包写盘
================================================================

用来回答一个问题：解出来的 /apex/*.apex 尾部全是 0，是镜像里本来就没有，
还是解包写盘写坏的？

    python3 vmos_apex_probe.py 原包.7z
    python3 vmos_apex_probe.py 改过的包.7z
    python3 vmos_apex_probe.py vmos_out/system          # 已解开的明文目录也行
    python3 vmos_apex_probe.py 原包.7z --ref 改过的包.7z  # 两包逐个 inode 对比
    python3 vmos_apex_probe.py 原包.7z --dump dump/      # 把读到的头尾存下来

它做的事
--------
1. 找镜像、读记录表（和 vmos_auto 同一套解析，不依赖解包结果）
2. 从索引里认出 /apex 下的每个文件，拿到 inode
3. 明文目录直接审、镜像模式列出每个卷的 size/offset
4. 按 **vmos 内核的视角** 判死活：zip 能否打开、每个条目 CRC 是否通过、
   有没有 original_apex / apex_payload.img、payload 是不是 ext4

零字节率只作参考（--zeros），不是判据 —— APEX 的 payload 是 STORED 存放的
稀疏 ext4，头 4 KB 里只有 30 B 文件头 + 16 B 文件名是非零的，98% 是零才正常。

退出码：0 正常，1 有不可用的 APEX，2 无法分析
"""

import argparse
import os
import shutil
import hashlib
import struct
import tempfile

import vmos_auto as va

VERSION = '2026.10.31.5'
hex_show = 4          # 最多给几个异常文件打十六进制
APEX_EXT = ('.apex', '.capex')
EXT4_OFF = 0x438      # ext4 superblock 魔数偏移
EXT4_MAGIC = b'\x53\xef'
# 照抄 AOSP apex_file.cpp 的 kFsType：内核按这三种挂 payload
FS_MAGIC = (('ext4', 1024 + 0x38, 2, b'\x53\xef'),
            ('f2fs', 1024, 4, b'\x10\x20\xf5\xf2'),
            ('erofs', 1024, 4, b'\xe2\xe1\xf5\xe0'))
MARK = {'ok': '✓', 'warn': '⚠', 'bad': '✘'}
SAMPLE_STEP = 1 << 20
SAMPLE_LEN = 4096


def human(n):
    if n is None or n < 0:
        return '?'
    if n < 1024:
        return f'{n} B'
    for unit in ('K', 'M', 'G', 'T'):
        n /= 1024.0
        if n < 1024 or unit == 'T':
            return f'{n:.1f} {unit}'


def zero_ratio(buf):
    if not buf:
        return None
    return buf.count(0) / len(buf)


def sample_zeros(im, off, size):
    """按 1 MB 步长抽样，估算整段里 0 的比例（20 MB 也只读 80 KB）"""
    if size <= 0:
        return None
    z = tot = 0
    step = SAMPLE_STEP
    p = off
    end = off + size
    while p < end:
        n = min(SAMPLE_LEN, end - p)
        b = bytes(im.data[p:p + n])
        z += b.count(0)
        tot += len(b)
        p += step
    return z / tot if tot else None


def collect_names(idx_dirs, log):
    """{文件名: inode}，来自索引（含分片）"""
    names = {}
    clash = {}
    for d in idx_dirs:
        for fn in sorted(os.listdir(d)):
            p = os.path.join(d, fn)
            if not os.path.isfile(p):
                continue
            try:
                with open(p, 'rb') as f:
                    items = va.index_lines(f.read()) or []
            except OSError:
                continue
            for name, ino in items:
                if ino in names and names[ino] != name:
                    clash.setdefault(ino, {names[ino]}).add(name)
                names[ino] = name
    if clash:
        log(f'  ! {len(clash)} 个 inode 在索引里有多个名字，按最后一个算')
    return names


def probe_one(images, ino, name):
    """返回每个卷一行；Volumes 的实际选择顺序 = 按镜像大小降序"""
    order = sorted(range(len(images)), key=lambda i: images[i].size, reverse=True)
    rows = []
    for k in order:
        im = images[k]
        r = im.recs.get(ino)
        if not r:
            continue
        sz, off = r['size'], r['offset']
        oob = off + sz > im.size
        hz = tz = sz_ratio = None
        if not oob and sz > 0:
            head = bytes(im.data[off:off + 4096])
            hz = head.count(0) / len(head) if head else None
            if sz >= 96:
                tail = bytes(im.data[off + sz - 96:off + sz])
                tz = tail.count(0) / len(tail)
            sz_ratio = sample_zeros(im, off, sz)
        rows.append({'idx': k, 'im': im, 'size': sz, 'off': off,
                     'oob': oob, 'head0': hz, 'tail0': tz, 'body0': sz_ratio})
    return rows


def dump_one(im, off, size, out):
    with open(out, 'wb') as f:
        f.write(bytes(im.data[off:off + min(64 << 10, size)]))
        if size > (128 << 10):
            f.write(b'\n--- tail ---\n')
            f.write(bytes(im.data[off + size - (64 << 10):off + size]))


def fmt_pct(v):
    return '  -  ' if v is None else f'{v * 100:5.1f}%'


def hexdump(b, width=16, indent='  '):
    out = []
    for i in range(0, len(b), width):
        c = b[i:i + width]
        hs = ' '.join(f'{x:02x}' for x in c)
        asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in c)
        out.append(f'{indent}{i:04x}  {hs:<{width * 3 - 1}}  {asc}')
    return '\n'.join(out)


def _is_somv_rec(b):
    """前 44 字节能不能当一条 SOMV inode 记录读通"""
    if len(b) < 44:
        return False
    mode = struct.unpack_from('<H', b, 0)[0]
    if (mode & 0xF000) not in (0x8000, 0x4000, 0xA000):
        return False
    size = struct.unpack_from('<I', b, 28)[0]
    off = struct.unpack_from('<I', b, 32)[0]
    return off >= (1 << 12) and size > 0


def head_signature(p, sz, n=64):
    """头部到底是什么东西 —— 这一步决定「是数据丢了」还是「offset 指错地方」。

    返回 (说明, 前 n 字节)。说明为空表示头部完全正常（PK\\x03\\x04）。
    """
    try:
        with open(p, 'rb') as f:
            b = f.read(n)
            head4k = f.read(4096 - len(b)) if n < 4096 else b''
    except OSError:
        return '', None
    if len(b) < 4:
        return '文件太短', b
    blob = b + head4k
    nz = len(blob) - blob.count(0)

    if b[:4] == b'SOMV':
        return '头是 SOMV 镜像魔数 → offset 指到镜像开头了', b
    if b[:4] == b'PK\x03\x04':
        return '', b
    if b[:4] == b'PK\x05\x06':
        return '只有 EOCD，是个空 zip', b
    if b[:2] == b'PK':
        return f'PK 但签名是 {b[:4].hex()} → 不是合法局部文件头', b
    if _is_somv_rec(b):
        mode = struct.unpack_from('<H', b, 0)[0]
        size = struct.unpack_from('<I', b, 28)[0]
        off = struct.unpack_from('<I', b, 32)[0]
        return (f'头像一条 SOMV inode 记录（mode={oct(mode)} size={size} '
                f'offset={off}）→ offset 落在记录表里'), b
    if nz <= 96:
        return f'头 4KB 只有 {nz} 个非零字节 → 基本是空洞/对齐填充', b
    return f'未知格式（前 4 字节 {b[:4].hex()}）', b


def find_apex_dir(base):
    for cand in ('apex', os.path.join('system', 'apex')):
        d = os.path.join(base, cand)
        if os.path.isdir(d):
            return d
    for dp, dns, _ in os.walk(base):
        if os.path.basename(dp) == 'apex':
            return dp
    return None


def tail_zeros(p, cap=1 << 20):
    """文件末尾连续 0 的字节数（最多数 1 MB）"""
    try:
        sz = os.path.getsize(p)
    except OSError:
        return 0
    n = 0
    with open(p, 'rb') as f:
        while n < min(sz, cap):
            step = min(65536, sz - n)
            f.seek(sz - n - step)
            b = f.read(step)
            stripped = b.rstrip(b'\0')
            n += len(b) - len(stripped)
            if stripped:
                break
    return n


def _crc_all(z, names):
    """逐条目读到尾，zipfile 会在关闭时校验 CRC"""
    bad = []
    for n in names:
        try:
            with z.open(n) as f:
                while f.read(1 << 20):
                    pass
        except Exception:
            bad.append(n)
    return bad


def payload_check(z, name):
    """apex_payload.img 必须 STORED 且是可挂载文件系统 —— 它要被 loop mount，
    压缩了就 mmap 不了。魔数表照抄 AOSP apex_file.cpp 的 kFsType。"""
    try:
        info = z.getinfo(name)
    except KeyError:
        return 'bad', f'缺 {name}'
    if info.compress_type != 0:
        return 'bad', (f'{name} 是压缩存储（method={info.compress_type}），'
                       f'内核 mmap 不了 → payload is compressed, cannot extract')
    need = max(off + ln for _, off, ln, _ in FS_MAGIC)
    if info.file_size < need:
        return 'bad', f'{name} 只有 {info.file_size} B，装不下文件系统头'
    try:
        with z.open(name) as f:
            b = f.read(need)
    except Exception as e:
        return 'bad', f'{name} 读不出：{str(e)[:40]}'
    for fs, off, ln, magic in FS_MAGIC:
        if b[off:off + ln] == magic:
            return 'ok', f'apex_payload.img {fs} {human(info.file_size)}'
    return 'warn', (f'apex_payload.img 无 ext4/erofs/f2fs 魔数'
                    f'（{human(info.file_size)}），内核挂不上')


def _inner_audit(blob, depth=0):
    """capex 的 original_apex 是内层 zip，真正的 payload 在它里面。
    返回 (状态, 说明, 内层 ZipFile 或 None)"""
    import io
    import zipfile
    try:
        z = zipfile.ZipFile(io.BytesIO(blob))
    except Exception as e:
        return 'bad', f'内层 original_apex 打不开：{str(e)[:40]}', None
    names = [n for n in z.namelist() if not n.endswith('/')]
    if 'apex_payload.img' not in names:
        return 'bad', f'内层缺 apex_payload.img（{len(names)} 条目）', None
    bad = _crc_all(z, names)
    if bad:
        return 'bad', f'内层 CRC 错 {len(bad)}/{len(names)}：{bad[0]}', None
    st, why = payload_check(z, 'apex_payload.img')
    return st, why, z


# 不再比对「外层副本 vs original_apex 内同名文件」。
# AOSP apex_file.cpp 的 ApexFile::Open 只从外层读 apex_manifest.pb / apex_pubkey，
# 从不与 original_apex 内比对；Decompress() 也只是把 original_apex 原样解出来。
# 实测真实 capex（21/21）外层 manifest 与内层就有差异，属正常构建形态。


def apex_audit(p):
    """按 vmos 内核的视角审一遍：能否当 zip 打开、CRC 全过没、
    original_apex 内层有没有 payload、payload 是不是 ext4。

    零字节比例不算判据 —— APEX 用 STORED 存稀疏 ext4，头部 4 KB 里
    只有 30 B zip 头 + 16 B 文件名是非零的，这是正常形态。
    返回 (状态, 说明, 条目数)。"""
    import zipfile
    try:
        z = zipfile.ZipFile(p)
    except Exception as e:
        return 'bad', f'zip 打不开：{str(e)[:50]}', 0
    names = [n for n in z.namelist() if not n.endswith('/')]
    if not names:
        return 'bad', 'zip 里没有条目', 0
    bad = _crc_all(z, names)
    if bad:
        return 'bad', f'CRC 错 {len(bad)}/{len(names)}：{bad[0]}', len(names)
    if 'original_apex' in names:
        try:
            info = z.getinfo('original_apex')
            blob = z.read('original_apex')
        except Exception as e:
            return 'bad', f'original_apex 读不出：{str(e)[:40]}', len(names)
        # capex 标准：original_apex 用 deflate(9) 压，其余条目 stored
        ct = info.compress_type
        outer = {0: 'stored', 8: 'deflate'}.get(ct, f'method={ct}')
        st, why, zi = _inner_audit(blob)
        return st, f'CRC 全过，original_apex {outer} → {why}', len(names)
    if 'apex_payload.img' in names:
        st, why = payload_check(z, 'apex_payload.img')
        return st, f'CRC 全过，{why}', len(names)
    return 'bad', f'CRC 全过但无 original_apex / apex_payload.img（{len(names)} 条目）', len(names)


def common_head(res, log):
    """头部指纹分组：正常文件各不同，若一大票文件前 4KB 完全一样，
    就说明它们读的是同一段内容 —— offset 指到同一个地方了，不是数据丢失。"""
    groups = {}
    for fn, r in res.items():
        hd = r.get('hd') or b''
        if len(hd) < 4096:
            continue
        groups.setdefault(hashlib.md5(hd).hexdigest()[:12], []).append(fn)
    if len(groups) < 1:
        return
    if len(groups) == 1 and sum(len(v) for v in groups.values()) >= 3:
        log(f'\n  ⚠ 全部 {sum(len(v) for v in groups.values())} 个文件前 4 KB 一模一样。'
            f'正常 APEX 各有各的 zip 头，不可能相同：')
        log('      → offset 全指到同一段内容了，是「指错位置」不是「数据丢失」')
        return
    same = [g for g in groups.values() if len(g) >= 3]
    if not same:
        return
    same.sort(key=len, reverse=True)
    biggest = same[0]
    log(f'\n  ⚠ {len(biggest)} 个文件的前 4 KB 完全一样（共 {len(groups)} 组）。'
        f'正常 APEX 各有各的 zip 头，不可能相同：')
    log(f'      {", ".join(biggest[:6])}'
        + (' …' if len(biggest) > 6 else ''))
    log('      → 这些文件的 offset 指向了同一段内容，是「指错位置」不是「数据丢失」')


def analyse_plain(base, label, dumpdir, log, show_zeros=False):
    """明文目录：按 vmos 内核的视角审 APEX —— zip 能否打开、CRC 是否全过、
    original_apex 内层有无 payload、payload 是不是 ext4"""
    d = find_apex_dir(base)
    if not d:
        log(f'[{label}] 没找到镜像，也没找到 apex 目录 —— 这像个普通目录')
        return None
    files = sorted((f for f in os.listdir(d) if f.lower().endswith(APEX_EXT)))
    log(f'[{label}] 明文目录 {d}，APEX {len(files)} 个')
    res, bad, warn = {}, 0, 0
    log(f'  {"文件":<38}{"大小":>9}  {"判":<2}{"条目":>4}  说明')
    for fn in files:
        p = os.path.join(d, fn)
        try:
            sz = os.path.getsize(p)
        except OSError:
            continue
        st, why, nent = apex_audit(p)
        if st == 'bad':
            bad += 1
        elif st == 'warn':
            warn += 1
        line = f'  {fn:<38}{human(sz):>9}  {MARK[st]}  {nent:>3}  {why}'
        log(line)
        if show_zeros and st != 'ok':
            hz = tz = body0 = None
            if sz >= 96:
                with open(p, 'rb') as f:
                    head = f.read(4096)
                    hz = head.count(0) / len(head) if head else None
                    f.seek(sz - 96)
                    tail = f.read(96)
                    tz = tail.count(0) / len(tail)
                    body0 = plain_sample_zeros(f, sz)
            log(f'      {"":38}{"":>9}     头部0率 {fmt_pct(hz)}  '
                f'尾部0率 {fmt_pct(tz)}  整段0率 {fmt_pct(body0)}')
        hd = b''
        try:
            with open(p, 'rb') as f:
                hd = f.read(4096)
        except OSError:
            pass
        res[fn] = {'size': sz, 'status': st, 'why': why, 'nent': nent, 'hd': hd}
    log(f'  → 不可用 {bad} / {len(files)}'
        + (f'，可疑 {warn}' if warn else ''))
    if bad:
        log('  说明：vmos 内核对每个 APEX 自己解 zip，找 original_apex / '
            'apex_payload.img，\n  打不开、CRC 错、payload 被压缩或不是 ext4 就 '
            '[APEX-JAR] abort boot，\n  症状正是 apex-tmp/vmos_apex_mnt 空、'
            'persist.sys.boot.reason=reboot,apexd-failed')
    elif warn:
        log('  → 没有硬伤，但有可疑项（见上）。若 boot 仍失败，优先查这些 ⚠ 的条目')
    else:
        log('  → 全部可用：APEX 这一环没有问题，boot 失败要往别处查'
            '（apex-tmp 目录权限、/data 可写性、SELinux 上下文）')
    return res


def plain_sample_zeros(f, size):
    if size <= 0:
        return None
    z = tot = 0
    p = 0
    while p < size:
        f.seek(p)
        b = f.read(min(SAMPLE_LEN, size - p))
        if not b:
            break
        z += b.count(0)
        tot += len(b)
        p += SAMPLE_STEP
    return z / tot if tot else None


def analyse(base, label, dumpdir, log, quiet=False, show_zeros=False):
    imgs, dirs, files = va.sniff(base)
    if not imgs:
        return analyse_plain(base, label, dumpdir, log, show_zeros)

    images = []
    for p in imgs:
        try:
            images.append(va.Image(p))
        except Exception as e:
            log(f'  ! {p}: {e}')

    names = collect_names(dirs, log)
    apex = sorted(((ino, n) for ino, n in names.items()
                   if n.lower().endswith(APEX_EXT)))
    log(f'[{label}] 镜像 {len(images)} 个，索引里 APEX 条目 {len(apex)} 个')

    if not apex:
        log('  索引里没有 .apex/.capex —— 索引可能不完整，无法定位名字')
        return None

    result = {}
    bad = warn = 0
    rectab = 0
    tmpd = tempfile.mkdtemp(prefix='apex_img_')
    log(f'  {"文件":<40}{"大小":>10}  判   条目  说明')
    for ino, name in apex:
        rows = probe_one(images, ino, name)
        if not rows:
            log(f'  {name:<40}{"-":>10}  ✘    0  镜像里没有这个 inode')
            bad += 1
            continue
        status = rows[0]
        for pos, r in enumerate(rows):
            if r['oob']:
                continue
            ds = r['im'].size - r['im'].data_size
            if 0 < r.get('off', 0) < ds:
                rectab += 1
        # 与明文模式同一套判据：先把镜像里的内容落到临时文件，再查 zip 结构
        p = os.path.join(tmpd, os.path.basename(name))
        try:
            with open(p, 'wb') as f:
                f.write(status['im'].data[status['off']:status['off'] + status['size']])
            st, why, nent = apex_audit(p)
        except Exception as e:
            st, why, nent = 'bad', f'读不出：{str(e)[:40]}', 0
        if st == 'bad':
            bad += 1
        elif st == 'warn':
            warn += 1
        extra = ''
        if st != 'ok':
            ds = status['im'].size - status['im'].data_size
            if 0 < status['off'] < ds:
                extra = f'；offset {status["off"]} 落在记录表内(数据区从 {ds} 起)'
            for pos, r in enumerate(rows[1:], start=1):
                if r['body0'] is not None and r['body0'] < 0.5:
                    extra += f'；卷 {pos} 里有数据，解包选错卷了'
                    break
        if show_zeros:
            extra += (f'  [头{fmt_pct(status["head0"])} 尾{fmt_pct(status["tail0"])} '
                      f'整段{fmt_pct(status["body0"])}]')
        log(f'  {name:<40}{human(status["size"]):>10}  {MARK[st]}  {nent:>3}  {why}{extra}')
        result[name] = {'size': status['size'], 'st': st,
                        'head0': status['head0'], 'tail0': status['tail0'],
                        'body0': status['body0'], 'why': why}
        if st == 'bad' and dumpdir:
            d = os.path.join(dumpdir, label.replace('/', '_'))
            os.makedirs(d, exist_ok=True)
            dump_one(status['im'], status['off'], status['size'],
                     os.path.join(d, name + '.bin'))
    shutil.rmtree(tmpd, ignore_errors=True)
    log(f'  → 不可用 {bad} / {len(apex)}' + (f'，可疑 {warn}' if warn else ''))
    if rectab:
        log(f'  ⚠ {rectab} 个 APEX 的 offset 落在 inode 记录表区间内，'
            f'读到的是记录不是数据')
        if rectab == len(apex):
            log('     → 判定：这张镜像的 offset 字段整体错位（写包时算错了），'
                '不是解包读坏、也不是数据丢失。\n'
                '       用原包对比一下：原包若正常，就是重打包那一步写坏了。')
    for im in images:
        im.close()
    return result


def main():
    ap = argparse.ArgumentParser(
        description='APEX 数据定位：镜像里到底有没有内容')
    ap.add_argument('inputs', nargs='+', help='压缩包或已解开的目录')
    ap.add_argument('--ref', help='对照包：逐个 APEX 比较两边卷内零率')
    ap.add_argument('--dump', help='把异常的 APEX 头 64KB+尾 64KB 存到这个目录')
    ap.add_argument('--hex', type=int, default=4, metavar='N',
                    help='给前 N 个异常文件打印头部十六进制（默认 4，0 关闭）')
    ap.add_argument('--zeros', action='store_true',
                    help='额外显示头部/尾部/整段零字节率（只作参考，不是判据）')
    ap.add_argument('--version', action='version', version=f'vmos_apex_probe {VERSION}')
    args = ap.parse_args()
    global hex_show
    hex_show = max(0, args.hex)

    tmp = tempfile.mkdtemp(prefix='apex_probe_')
    try:
        bases = []
        for raw in args.inputs:
            src = os.path.abspath(raw)
            if os.path.isdir(src):
                bases.append((os.path.basename(src), src))
                continue
            d = va.materialize(src, os.path.join(tmp, os.path.basename(src)))
            bases.append((os.path.basename(src), d))

        res = {}
        for label, base in bases:
            res[label] = analyse(base, label, args.dump, print,
                                 show_zeros=args.zeros)

        if args.ref:
            ref = os.path.abspath(args.ref)
            rbase = ref if os.path.isdir(ref) else \
                va.materialize(ref, os.path.join(tmp, 'ref'))
            rlabel = os.path.basename(ref)
            print()
            rres = analyse(rbase, rlabel, None, print, show_zeros=args.zeros)
            if len(bases) == 1:
                compare(res.get(bases[0][0]), rres, bases[0][0], rlabel, print)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def compare(a, b, la, lb, log):
    """两边逐个 APEX 比大小、可用性、头部指纹"""
    if not a or not b:
        log('\n对比：有一边没跑出结果，跳过')
        return
    first = next(iter(a.values()))
    if not isinstance(first, dict) or 'status' not in first:
        log('\n对比：镜像模式不逐项比，请两边都用明文目录，或分别跑两次看判定')
        return
    common = sorted(set(a) & set(b))
    log(f'\n对比（{la} ← → {lb}）：共同 {len(common)} 个 APEX')
    log(f'  {"文件":<38}{"大小":>9}  {la[:10]:>10}  {lb[:10]:>10}  判定')
    diff = 0
    for n in common:
        x, y = a[n], b[n]
        sx, sy = x.get('status', '?'), y.get('status', '?')
        verdict = '一致'
        if x['size'] != y['size']:
            verdict = f'⚠ 大小不同 {x["size"]:,} → {y["size"]:,}'
            diff += 1
        elif sx != sy:
            verdict = f'⚠ 可用性变了 {sx} → {sy}'
            diff += 1
        elif x.get('hd') != y.get('hd'):
            verdict = '⚠ 头部不同'
            diff += 1
        log(f'  {n:<38}{human(x["size"]):>9}  {MARK.get(sx, "?"):>10}  '
            f'{MARK.get(sy, "?"):>10}  {verdict}')
    extra = set(a) - set(b)
    missing = set(b) - set(a)
    if extra:
        log(f'  只在 {la} 里：{len(extra)} 个')
    if missing:
        log(f'  只在 {lb} 里：{len(missing)} 个')
    log(f'  → 差异 {diff} / {len(common)}')


if __name__ == '__main__':
    main()
