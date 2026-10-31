#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vmos_apk_sigcheck.py — 真正验证 APK v2 签名是否有效

区别在于：vmos_apk_check 只看「签名块存不存在」，本工具会
把整个 APK 重算一遍分块摘要，再用证书公钥验一次 RSA，
所以能回答「签名结构在，但摘要对不对」。

改完 assets 再重签，最常见的失败是：
  · 签完又用 ZIP 工具动了一下 → 摘要全废，结构看着完整
  · 签名工具写了 v2 块但没更新 EOCD 的 central directory 偏移
  · 证书和签名值不匹配（少见，但工具写错时会）

用法:
    python3 vmos_apk_sigcheck.py 你的包.apk
    python3 vmos_apk_sigcheck.py 你的包.apk --dump-cert cert.der
"""

import argparse
import hashlib
import os
import struct
import sys

VERSION = '2026.10.31.2'

# ══════════════════════ 内置 DER / RSA 验签（纯标准库）══════════════════════
# 原为独立模块 vmos_apk_pki.py，为了单文件可跑直接内联。
# 不依赖 cryptography / openssl / JDK，Python 3.8+ 即可。

_HASHES = {'sha256': hashlib.sha256, 'sha512': hashlib.sha512}

# PKCS#1 v1.5 的 DigestInfo 头（RFC 8017 A.2.4）
_DIGEST_INFO = {
    'sha256': bytes.fromhex('3031300d060960864801650304020105000420'),
    'sha512': bytes.fromhex('3051300d060960864801650304020305000440'),
}


def _der_read(buf, off):
    if off + 2 > len(buf):
        raise ValueError(f'DER 越界 @ {off}')
    tag = buf[off]
    off += 1
    ln = buf[off]
    off += 1
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4:
            raise ValueError('DER 长度字段非法')
        ln = int.from_bytes(buf[off:off + n], 'big')
        off += n
    end = off + ln
    if end > len(buf):
        raise ValueError(f'DER 长度越界：{off}+{ln} > {len(buf)}')
    return tag, off, end


def _der_children(buf, start, end):
    out = []
    p = start
    while p < end:
        tag, cs, ce = _der_read(buf, p)
        out.append((tag, cs, ce))
        p = ce
    return out


def _der_expect(buf, tag, what):
    t, s, e = _der_read(buf, 0)
    if t != tag:
        raise ValueError(f'{what} 期望 tag {tag:#x}，实际 {t:#x}')
    return s, e


def _der_encode_len(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(body)]) + body


def _slice_seq(buf, cs, ce):
    """把 SEQUENCE 的内容重新包成完整 TLV，方便递归解析。"""
    body = buf[cs:ce]
    return b'\x30' + _der_encode_len(len(body)) + body


def rsa_from_pkcs1(buf):
    """RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }"""
    s, e = _der_expect(buf, 0x30, 'RSAPublicKey')
    kids = _der_children(buf, s, e)
    if len(kids) < 2:
        raise ValueError('RSAPublicKey 缺少 n/e')

    def integer(i):
        t, cs, ce = kids[i]
        if t != 0x02:
            raise ValueError('期望 INTEGER')
        return int.from_bytes(buf[cs:ce], 'big')

    return integer(0), integer(1)


def rsa_from_spki(buf):
    """SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }"""
    s, e = _der_expect(buf, 0x30, 'SubjectPublicKeyInfo')
    kids = _der_children(buf, s, e)
    if len(kids) < 2 or kids[1][0] != 0x03:
        raise ValueError('SPKI 结构异常')
    cs, ce = kids[1][1], kids[1][2]
    return rsa_from_pkcs1(buf[cs + 1:ce])   # 跳过 BIT STRING 的未使用位计数


def rsa_from_public_der(buf):
    """v2 的 public_key 字段是 SPKI；也接受裸 PKCS#1。"""
    try:
        return rsa_from_spki(buf)
    except Exception:
        return rsa_from_pkcs1(buf)


def rsa_from_cert(cert_der):
    """从 X.509 证书里挖出 RSA 公钥 (n, e)。"""
    s, e = _der_expect(cert_der, 0x30, 'Certificate')
    kids = _der_children(cert_der, s, e)
    tbs = _der_children(cert_der, kids[0][1], kids[0][2])
    idx = 1 if tbs and tbs[0][0] == 0xA0 else 0   # [0] version 可选
    if len(tbs) < idx + 6:
        raise ValueError('tbsCertificate 字段不足')
    return rsa_from_spki(_slice_seq(cert_der, tbs[idx + 5][1], tbs[idx + 5][2]))


def _mgf1(seed, length, hashname):
    h = _HASHES[hashname]
    out = b''
    counter = 0
    while len(out) < length:
        out += h(seed + counter.to_bytes(4, 'big')).digest()
        counter += 1
    return out[:length]


def _emsa_pkcs1_v15(msg, em_len, hashname):
    d = _HASHES[hashname](msg).digest()
    t = _DIGEST_INFO[hashname] + d
    if em_len < len(t) + 11:
        raise ValueError('模数太小，放不下 DigestInfo')
    return b'\x00\x01' + b'\xff' * (em_len - len(t) - 3) + b'\x00' + t


def rsa_pkcs1_verify(n, e, sig, msg, hashname='sha256'):
    k = (n.bit_length() + 7) // 8
    sig = sig.lstrip(b'\x00')
    if len(sig) != k:
        return False, f'签名长度 {len(sig)} 与模长 {k} 不符'
    s = int.from_bytes(sig, 'big')
    if s >= n:
        return False, '签名值 ≥ 模数（模数或签名不匹配）'
    em = pow(s, e, n).to_bytes(k, 'big')
    try:
        expect = _emsa_pkcs1_v15(msg, k, hashname)
    except ValueError as ex:
        return False, str(ex)
    if em == expect:
        return True, ''
    return False, f'填充不符（EM 前 16 字节 {em[:16].hex()}）'


def rsa_pss_verify(n, e, sig, msg, hashname='sha256', salt_len=None):
    k = (n.bit_length() + 7) // 8
    em_bits = n.bit_length() - 1
    em_len = (em_bits + 7) // 8
    sig = sig.lstrip(b'\x00')
    if len(sig) != k:
        return False, f'签名长度 {len(sig)} 与模长 {k} 不符'
    s = int.from_bytes(sig, 'big')
    if s >= n:
        return False, '签名值 ≥ 模数'
    em = pow(s, e, n).to_bytes(em_len, 'big')
    h = _HASHES[hashname]
    h_len = h(b'').digest_size
    if salt_len is None:
        salt_len = h_len
    if em_len < h_len + salt_len + 2:
        return False, '模数过小，放不下 PSS 结构'
    if em[-1] != 0xBC:
        return False, f'EM 末字节应为 0xBC，实际 {em[-1]:#x}'
    masked_db = em[:em_len - h_len - 1]
    hh = em[em_len - h_len - 1:-1]
    top = 8 * em_len - em_bits
    if top and (masked_db[0] >> (8 - top)):
        return False, 'DB 最高位不为 0'
    db = bytes(a ^ b for a, b in zip(masked_db, _mgf1(hh, len(masked_db), hashname)))
    if top:
        db = bytes([db[0] & (0xFF >> top)]) + db[1:]
    ps_len = em_len - h_len - salt_len - 2
    if any(db[:ps_len]):
        return False, 'PS 段不全为 0'
    if db[ps_len] != 0x01:
        return False, '缺少 0x01 分隔符'
    salt = db[-salt_len:] if salt_len else b''
    h2 = h(b'\x00' * 8 + h(msg).digest() + salt).digest()
    return (h2 == hh), '' if h2 == hh else 'H 值不匹配'


def rsa_verify(kind, n, e, sig, msg, hashname):
    if kind == 'pkcs1':
        return rsa_pkcs1_verify(n, e, sig, msg, hashname)
    if kind == 'pss':
        return rsa_pss_verify(n, e, sig, msg, hashname)
    raise NotImplementedError(f'暂不支持 {kind}（本工具只覆盖 RSA 的两种填充）')


# ═══════════════════════════════════════════════════════════════════════════

OK, BAD, WARN, INFO = '\u2714', '\u2718', '\u26a0', '\u00b7'

BLOCK_ID_V2 = 0x7109871a
BLOCK_ID_V3 = 0xf05368c0
BLOCK_ID_V31 = 0x1b93ad61

ALGS = {
    0x0101: ('RSASSA-PSS + SHA2-256', 'pss', 'sha256'),
    0x0102: ('RSASSA-PSS + SHA2-512', 'pss', 'sha512'),
    0x0103: ('RSASSA-PKCS1-v1_5 + SHA2-256', 'pkcs1', 'sha256'),
    0x0104: ('RSASSA-PKCS1-v1_5 + SHA2-512', 'pkcs1', 'sha512'),
    0x0201: ('ECDSA + SHA2-256', 'ecdsa', 'sha256'),
    0x0202: ('ECDSA + SHA2-512', 'ecdsa', 'sha512'),
    0x0301: ('DSA + SHA2-256', 'dsa', 'sha256'),
}

CHUNK = 1 << 20  # v2 规定 1 MiB


def lp(buf, off):
    """读一个 uint32 长度前缀的片段。"""
    if off + 4 > len(buf):
        raise ValueError('长度字段越界')
    n = struct.unpack_from('<I', buf, off)[0]
    if off + 4 + n > len(buf):
        raise ValueError(f'片段长度 {n} 越界（剩余 {len(buf) - off - 4}）')
    return buf[off + 4:off + 4 + n], off + 4 + n


def lp_seq(buf, off):
    """读一个由 length-prefixed 元素组成的序列。"""
    seq, off = lp(buf, off)
    items, p = [], 0
    while p < len(seq):
        item, p = lp(seq, p)
        items.append(item)
    return items, off


# ────────────────────────────── 定位 ──────────────────────────────
def locate(path):
    size = os.path.getsize(path)
    with open(path, 'rb') as f:
        f.seek(max(0, size - 65557))
        tail = f.read()
        rel = tail.rfind(b'PK\x05\x06')
        if rel < 0:
            raise SystemExit('找不到 EOCD，不是合法 APK')
        eocd_off = size - len(tail) + rel
        f.seek(eocd_off)
        eocd = f.read(22)

        cd_size, cd_off = struct.unpack_from('<II', eocd, 12)
        if cd_off == 0xFFFFFFFF or cd_size == 0xFFFFFFFF:
            raise SystemExit('EOCD 用了 zip64 记录，本工具暂不支持这种 APK')

        f.seek(cd_off - 24)
        foot = f.read(24)
        if len(foot) < 24 or foot[8:24] != b'APK Sig Block 42':
            return dict(size=size, eocd_off=eocd_off, eocd=eocd,
                        cd_off=cd_off, cd_size=cd_size,
                        block_start=None, blocks=[])

        block_size = struct.unpack('<Q', foot[:8])[0]
        block_start = cd_off - block_size - 8
        if block_start < 0:
            raise SystemExit(f'签名块长度 {block_size} 超出文件范围')

        f.seek(block_start)
        head = struct.unpack('<Q', f.read(8))[0]
        blocks = []
        p = block_start + 8
        end = cd_off - 24
        while p < end:
            f.seek(p)
            ln = struct.unpack('<Q', f.read(8))[0]
            idd = struct.unpack('<I', f.read(4))[0]
            blocks.append((idd, f.read(ln - 4)))
            p += 8 + ln
        return dict(size=size, eocd_off=eocd_off, eocd=eocd,
                    cd_off=cd_off, cd_size=cd_size,
                    block_start=block_start, block_size=block_size,
                    head_len=head, blocks=blocks)


# ─────────────────────── 计算文件内容摘要 ───────────────────────
def _chunks(f, start, end):
    out = []
    pos = start
    while pos < end:
        n = min(CHUNK, end - pos)
        f.seek(pos)
        data = f.read(n)
        h = hashlib.sha256()
        h.update(b'\xa5')
        h.update(struct.pack('<I', n))
        h.update(data)
        out.append(h.digest())
        pos += n
    return out


def content_digest(path, info, alg='sha256'):
    """APK Signature Scheme v2 的 content digest。

    三个区间：内容区 / central directory / EOCD（把 EOCD 里的 cd_off 换成签名块起点）。
    """
    eocd_off = info['eocd_off']
    eocd = bytearray(info['eocd'])
    # EOCD 的 16 字节处是 central directory 偏移，验签时要替换成签名块起点
    struct.pack_into('<I', eocd, 16, info['block_start'])

    digests = []
    with open(path, 'rb') as f:
        digests += _chunks(f, 0, info['block_start'])
        digests += _chunks(f, info['cd_off'], eocd_off)
        h = hashlib.sha256()
        h.update(b'\xa5')
        h.update(struct.pack('<I', len(eocd)))
        h.update(bytes(eocd))
        digests.append(h.digest())

    top = hashlib.new(alg)
    top.update(b'\x5a')
    top.update(struct.pack('<I', len(digests)))
    for d in digests:
        top.update(d)
    return top.digest(), len(digests)


# ────────────────────────── 解析 v2 块 ──────────────────────────
def parse_v2(payload):
    signers_raw, _ = lp_seq(payload, 0)
    signers = []
    for s in signers_raw:
        signed_data, off = lp(s, 0)
        signatures, off2 = lp_seq(s, off)
        public_key, off3 = lp(s, off2)
        # signed_data = 摘要序列 + 证书序列 + 附加属性序列
        digests, p = lp_seq(signed_data, 0)
        certs, p = lp_seq(signed_data, p)

        sigs = []
        q = 0
        for item in signatures:
            alg_id = struct.unpack_from('<I', item, 0)[0]
            val, _ = lp(item, 4)
            sigs.append((alg_id, val, item))
        digs = []
        q = 0
        for item in digests:
            alg_id = struct.unpack_from('<I', item, 0)[0]
            val, _ = lp(item, 4)
            digs.append((alg_id, val))
        signers.append(dict(signed_data=signed_data, signatures=sigs,
                            public_key=public_key, digests=digs,
                            certificates=certs))
    return signers


def verify_rsa(pubkey_bytes, sig_bytes, signed_data, kind, hashname):
    """纯标准库验签：返回 (ok, 原因)。不再依赖 cryptography。"""
    n, e = rsa_from_public_der(pubkey_bytes)
    return rsa_verify(kind, n, e, sig_bytes, signed_data, hashname)


def cert_sha256(der):
    return hashlib.sha256(der).hexdigest()


def _axml_strings(data, off):
    """解析 RES_STRING_POOL chunk，返回字符串列表。"""
    _typ, _hsz, _sz = struct.unpack_from('<HHI', data, off)
    count, _style, flags = struct.unpack_from('<III', data, off + 8)
    strings_start = struct.unpack_from('<I', data, off + 20)[0]
    offs = struct.unpack_from('<%dI' % count, data, off + struct.unpack_from('<H', data, off + 2)[0])
    base = off + strings_start
    out = []
    for o in offs:
        p = base + o
        try:
            if flags & 0x100:                       # UTF-8
                n = data[p]
                p += 1
                if n & 0x80:
                    n = ((n & 0x7F) << 8) | data[p]
                    p += 1
                out.append(data[p:p + n].decode('utf-8', 'replace'))
            else:                                    # UTF-16
                n = struct.unpack_from('<H', data, p)[0]
                p += 2
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | struct.unpack_from('<H', data, p)[0]
                    p += 2
                out.append(data[p:p + n * 2].decode('utf-16-le', 'replace'))
        except Exception:
            out.append('')
    return out


def _axml_elements(data):
    """极简二进制 XML 解析，返回 [(元素名, {属性名: 值})]。"""
    if len(data) < 8 or struct.unpack_from('<HHI', data, 0)[0] != 0x0003:
        return []
    strings = _axml_strings(data, 8)
    out = []
    off, end = 8, len(data)
    while off + 8 <= end:
        typ, _hsz, sz = struct.unpack_from('<HHI', data, off)
        if sz <= 0:
            break
        if typ == 0x0102:                            # START_TAG
            name_i = struct.unpack_from('<I', data, off + 20)[0]
            attr_start, attr_size, attr_count = struct.unpack_from('<HHH', data, off + 24)
            attrs, p = {}, off + 16 + attr_start
            for _ in range(attr_count):
                try:
                    _ns, an, _raw = struct.unpack_from('<III', data, p)
                    dtype = data[p + 15]
                    dval = struct.unpack_from('<I', data, p + 16)[0]
                except Exception:
                    break
                key = strings[an] if an < len(strings) else f'@{an}'
                if dtype == 0x10:
                    val = dval
                elif dtype == 0x03:
                    val = strings[dval] if dval < len(strings) else ''
                elif dtype == 0x12:
                    val = bool(dval)
                else:
                    val = dval
                attrs[key] = val
                p += attr_size or 20
            out.append((strings[name_i] if name_i < len(strings) else '', attrs))
        off += sz
    return out


def install_facts(apk):
    """与安装成败直接相关的字段：版本号、SDK 范围、ABI、体积。"""
    import zipfile
    facts = {}
    with zipfile.ZipFile(apk) as z:
        try:
            for name, attrs in _axml_elements(z.read('AndroidManifest.xml')):
                if name == 'manifest':
                    for k in ('package', 'versionCode', 'versionName'):
                        facts[k] = attrs.get(k)
                elif name == 'uses-sdk':
                    facts['minSdk'] = attrs.get('minSdkVersion')
                    facts['targetSdk'] = attrs.get('targetSdkVersion')
        except Exception as ex:
            facts['manifest_error'] = str(ex)
        infos = z.infolist()
        facts['abis'] = sorted({i.filename.split('/')[1] for i in infos
                                if i.filename.startswith('lib/')
                                and i.filename.count('/') >= 2})
        facts['compressed'] = sum(i.compress_size for i in infos)
        facts['total'] = sum(i.file_size for i in infos)
        facts['members'] = len(infos)
    return facts


# ────────────────────────────── 主流程 ──────────────────────────────
def main():
    ap = argparse.ArgumentParser(description='验证 APK v2 签名（摘要 + RSA）')
    ap.add_argument('apk')
    ap.add_argument('--dump-cert', metavar='FILE', help='把签名证书导出成 DER')
    ap.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    args = ap.parse_args()

    if not os.path.isfile(args.apk):
        sys.exit(f'文件不存在：{args.apk}')

    info = locate(args.apk)
    size = info['size']
    print(f'文件 {args.apk}  ({size / 1048576:.0f} MB)')

    # ── 结构 ──
    print('\n【1】结构')
    if info['block_start'] is None:
        print(f'  {BAD} 没有 APK Signing Block → 只有 v1 或完全未签名')
        print('  结论：targetSdk 26+ 的包这样一定装不上，必须重签 v2')
        return 1

    print(f'  {OK} 签名块存在：{info["block_start"]:,} ~ {info["cd_off"]:,}'
          f'（{info["block_size"]:,} 字节）')
    if info['head_len'] != info['block_size']:
        print(f'  {BAD} 头尾长度不一致：头 {info["head_len"]} / 尾 {info["block_size"]}')
    else:
        print(f'  {OK} 头尾长度一致')

    # EOCD 的 cd_off 必须指向 central directory，不能指到签名块里
    expect_cd = info['block_start']
    if info['cd_off'] <= info['block_start']:
        print(f'  {BAD} central directory 偏移 {info["cd_off"]:,} 落在签名块内，文件结构已坏')
    else:
        print(f'  {OK} central directory 偏移正常（{info["cd_off"]:,}）')

    # 校验 local header：随便抽几个，看偏移是否真的指向 PK\x03\x04
    try:
        import zipfile
        with zipfile.ZipFile(args.apk) as z:
            bad = 0
            sample = z.infolist()
            for it in (sample[:3] + sample[-3:]):
                with open(args.apk, 'rb') as f:
                    f.seek(it.header_offset)
                    if f.read(4) != b'PK\x03\x04':
                        bad += 1
            print(f'  {OK if not bad else BAD} local header 抽查 '
                  f'{len(sample[:3] + sample[-3:])} 个，异常 {bad}')
    except Exception as e:
        print(f'  {WARN} zip 读取失败：{e}')

    v2 = None
    for idd, payload in info['blocks']:
        name = {BLOCK_ID_V2: 'v2', BLOCK_ID_V3: 'v3', BLOCK_ID_V31: 'v3.1'}.get(idd, hex(idd))
        print(f'  {INFO} 块 {name}（{len(payload):,} 字节）')
        if idd == BLOCK_ID_V2:
            v2 = payload

    if v2 is None:
        print(f'  {BAD} 没有 v2 块')
        return 1

    # ── 摘要 ──
    print('\n【2】内容摘要')
    try:
        actual, nchunk = content_digest(args.apk, info)
    except Exception as e:
        print(f'  {BAD} 计算失败：{e}')
        return 1
    print(f'  {INFO} 全文件 {nchunk} 个 1 MiB 分块，合并摘要 {actual.hex()[:32]}…')

    try:
        signers = parse_v2(v2)
    except Exception as e:
        print(f'  {BAD} v2 块解析失败：{e}')
        return 1

    print(f'  {INFO} v2 里 {len(signers)} 个签名者')
    all_ok = True
    for i, s in enumerate(signers, 1):
        print(f'  签名者 #{i}')
        if s['certificates']:
            der = s['certificates'][0]
            print(f'    {INFO} 证书 SHA-256 {cert_sha256(der)[:32]}…（{len(der)} 字节）')
            if args.dump_cert:
                with open(args.dump_cert, 'wb') as f:
                    f.write(der)
                print(f'    {INFO} 已导出 {args.dump_cert}')

        # 摘要比对
        matched = None
        for alg_id, dg in s['digests']:
            if alg_id in (0x0101, 0x0103, 0x0201, 0x0301):
                matched = (alg_id, dg)
                break
        if matched:
            alg_name = ALGS.get(matched[0], ('未知',))[0]
            same = matched[1] == actual
            print(f'    {OK if same else BAD} 摘要对比（{alg_name}）'
                  f'{"一致" if same else "不一致"}')
            if not same:
                print(f'        签名里的：{matched[1].hex()[:48]}…')
                print(f'        实算的  ：{actual.hex()[:48]}…')
                all_ok = False
        else:
            print(f'    {WARN} 找不到 SHA2-256 级别的摘要条目')
            all_ok = False

        # RSA 验签（纯标准库，不依赖 cryptography）
        verified = False
        unsupported = False
        for alg_id, sig, raw in s['signatures']:
            meta = ALGS.get(alg_id)
            if not meta:
                print(f'    {WARN} 未知签名算法 {alg_id:#x}')
                continue
            name, kind, hashname = meta
            try:
                ok, why = verify_rsa(s['public_key'], sig, s['signed_data'], kind, hashname)
            except NotImplementedError as ex:
                print(f'    {WARN} 本工具只实现了 RSA，{name} 未验证：{ex}')
                unsupported = True
                continue
            except Exception as ex:
                print(f'    {WARN} 公钥解析失败（{name}）：{ex}')
                unsupported = True
                continue
            if ok:
                print(f'    {OK} 签名验证通过（{name}）')
                verified = True
                break
            print(f'    {BAD} 签名验证失败（{name}）：{why}')
            all_ok = False
        if not verified and not unsupported and not all_ok:
            pass
        if not verified and not unsupported:
            print(f'    {BAD} 没有可验证的签名值')
            all_ok = False

        # 公钥与证书是否一致（v2 规范要求一致，不一致说明签名块被拼过）
        if s.get('certificates') and s.get('public_key'):
            try:
                n1, e1 = rsa_from_public_der(s['public_key'])
                n2, e2 = rsa_from_cert(s['certificates'][0])
                if (n1, e1) == (n2, e2):
                    print(f'    {OK} 签名公钥与证书公钥一致')
                else:
                    print(f'    {BAD} 签名公钥与证书公钥不一致 → 签名块被拼接/改写')
                    all_ok = False
            except Exception:
                pass

    # ── 安装关键字段 ──
    print('\n【3】安装关键字段')
    facts = install_facts(args.apk)
    if facts.get('manifest_error'):
        print(f'  {WARN} manifest 解析失败：{facts["manifest_error"]}')
    pkg = facts.get('package')
    vc = facts.get('versionCode')
    print(f'  · 包名 {pkg}  versionCode {vc}（{facts.get("versionName")}）')
    print(f'  · minSdk {facts.get("minSdk")} / targetSdk {facts.get("targetSdk")}')
    print(f'  · ABI {", ".join(facts.get("abis") or ["无 native lib"])}')
    comp = facts.get('compressed') or 0
    print(f'  · 压缩后 {comp / 1048576:.0f} MB，成员 {facts.get("members")} 个')
    print(f'  · 安装峰值需求 ≈ {comp * 2 / 1073741824 + 0.2:.1f} GB 空闲'
          f'（复制一份 + 落地一份 + dexopt）')
    if pkg and vc and vc < 11301:
        print(f'  {BAD} versionCode {vc} 低于官方 11301 → '
              'INSTALL_FAILED_VERSION_DOWNGRADE')

    print('\n【4】结论')
    if all_ok and verified:
        print(f'  {OK} v2 签名有效：摘要一致、RSA 通过')
        print('  → 签名不是安装失败的原因，去看 INSTALL_* 错误码（空间/降级/已装同签名）')
    elif all_ok and unsupported:
        print(f'  {OK} 摘要一致，签名结构完整（本工具未覆盖的算法未做验签）')
        print('  → 基本可判定签名有效；若仍装不上，问题不在签名')
    else:
        print(f'  {BAD} v2 签名无效')
        print('  → 多半是签名之后又动过文件，或签名工具没写对，需重新 zipalign + 签名')

    return 0 if (all_ok and (verified or unsupported)) else 1


if __name__ == '__main__':
    sys.exit(main())
