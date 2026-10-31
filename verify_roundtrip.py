#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""往返自检：解包 → 打包 → 再解包，逐项比对内容是否无损。

用法:
    python3 verify_roundtrip.py <包.zip|包.7z|整包目录|分区目录> [--name 分区名]

它不会改动你的原文件，全部在临时目录里做，结束自动清理。
判定标准：解包结果 A 与"打回镜像后再解包"的结果 B 完全一致
（路径、类型、大小、内容 sha1、链接目标、权限位）。

为什么用这个判据：它不需要相信任何一方，只要 A→镜像→B 走通且 B==A，
就说明打包器和解包器对同一套格式的理解是一致的、无损的。
"""
import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
AUTO = os.path.join(HERE, 'vmos_auto.py')
PACK = os.path.join(HERE, 'vmos_pack.py')


def run(cmd):
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True, errors='replace')
    if r.returncode != 0:
        print(r.stdout[-3000:])
        raise SystemExit(f'命令失败: {" ".join(cmd)}')
    return r.stdout


def snapshot(base):
    """记录一棵树的全部可比较属性"""
    out = {}
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames.sort()
        for n in dirnames:
            p = os.path.join(dirpath, n)
            rel = os.path.relpath(p, base).replace(os.sep, '/')
            if os.path.islink(p):
                out[rel] = ('link', os.readlink(p))
            else:
                out[rel] = ('dir', oct(os.lstat(p).st_mode & 0o7777))
        for n in filenames:
            p = os.path.join(dirpath, n)
            rel = os.path.relpath(p, base).replace(os.sep, '/')
            if os.path.islink(p):
                out[rel] = ('link', os.readlink(p))
                continue
            st = os.lstat(p)
            h = hashlib.sha1()
            with open(p, 'rb') as f:
                while True:
                    b = f.read(1 << 20)
                    if not b:
                        break
                    h.update(b)
            out[rel] = ('file', st.st_size, h.hexdigest(),
                        oct(st.st_mode & 0o7777))
    return out


def diff(a, b):
    only_a = sorted(set(a) - set(b))
    only_b = sorted(set(b) - set(a))
    changed = sorted(k for k in a if k in b and a[k] != b[k])
    return only_a, only_b, changed


def main():
    ap = argparse.ArgumentParser(description='VMOS 分区往返自检')
    ap.add_argument('src', help='包或目录')
    ap.add_argument('--name', help='只测指定分区（默认第一个）')
    ap.add_argument('--keep', action='store_true', help='保留临时目录')
    args = ap.parse_args()

    src = os.path.abspath(args.src)
    if not os.path.exists(src):
        sys.exit(f'不存在: {src}')

    tmp = tempfile.mkdtemp(prefix='vmos_rt_')
    try:
        a_dir = os.path.join(tmp, 'A')
        b_dir = os.path.join(tmp, 'B')
        c_dir = os.path.join(tmp, 'C')

        print('[1/3] 解包 ...')
        run([sys.executable, AUTO, src, '-o', a_dir])

        parts = []
        for d in sorted(os.listdir(a_dir)):
            p = os.path.join(a_dir, d)
            if os.path.isdir(p) and not d.startswith('.'):
                # 分区目录应该有内容（索引/明文），排除 _recovered 之类
                if os.listdir(p):
                    parts.append(d)
        if not parts:
            sys.exit('没有解出任何分区')
        name = args.name or parts[0]
        if name not in parts:
            sys.exit(f'没有分区 {name}，可选: {", ".join(parts)}')
        print(f'      分区: {name}  ({len(parts)} 个: {", ".join(parts)})')

        print('[2/3] 打回镜像 ...')
        run([sys.executable, PACK, os.path.join(a_dir, name),
             '-o', b_dir, '--name', name])

        print('[3/3] 再解包一次 ...')
        run([sys.executable, AUTO, os.path.join(b_dir, name), '-o', c_dir])
        back = None
        for d in sorted(os.listdir(c_dir)):
            if os.path.isdir(os.path.join(c_dir, d)):
                back = os.path.join(c_dir, d)
                break
        if not back:
            sys.exit('重新打包的镜像解不出来')

        sa = snapshot(os.path.join(a_dir, name))
        sb = snapshot(back)
        only_a, only_b, changed = diff(sa, sb)

        print('\n' + '=' * 56)
        print(f'A（原解包）  {len(sa)} 项')
        print(f'B（回打包再解）{len(sb)} 项')
        if not (only_a or only_b or changed):
            print('\n结果: ✓ 完全一致，打包/解包为无损互逆')
            print('=' * 56)
            return 0
        print(f'\n结果: ✗ 有差异')
        print(f'  仅 A 有 {len(only_a)}: {only_a[:8]}')
        print(f'  仅 B 有 {len(only_b)}: {only_b[:8]}')
        print(f'  属性不同 {len(changed)}:')
        for k in changed[:10]:
            print(f'    {k}\n      A={sa[k]}\n      B={sb[k]}')
        print('=' * 56)
        return 1
    finally:
        if args.keep:
            print(f'\n临时目录: {tmp}')
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
