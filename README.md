# VMOS Plus Rom解包工具
## 仅适用于VMOS Plus Android15版本
## 使用方法：
```bash
解包: python3 vmos_auto.py rom.7z
打包: python3 vmos_db.py 原包.7z ./vmos_out -o 输出修改.zip
修复sha-256: python3 vmos_meta_fix.py 原包.7z 修改的.zip -o fix.zip
```

| 脚本 | 作用 |
|---|---|
| `vmos_auto.py` | 喂 zip / 7z / tar / 目录 → 自动识别所有分区，还原出目录和文件 |
| `vmos_pack.py` | 把改好的目录 / zip → 打包回 `.so` + `vblock` + `00000000` 原格式 |
| `vmos_rom.py` | **整个大包一次重打**：原包 + 改过的目录 → 新的完整 zip / 7z |
| `vmos_check.py` | **启动前自检**：复刻 VMOS 的校验链，告诉你包坏在哪 |
| `vmos_inode_pack.py` | **按 inode 回填**：无索引 / 无文件名也能改包，只动目标 inode |
| `vmos_boot_diag.py` | **日志定因**：把 VMOS 启动日志读成"断在哪一环 + 下一条命令" |
| `vmos_sidecar_fix.py` | **同步启动侧车登记**：改了 6 个侧车 .so 就重算 sha256/size |
| `vmos_rom_diff.py` | **以官方包为基线对比**：逐 inode / 索引 / 明文 / vblock 四路，直接说是哪一步改坏了 |
| `vmos_lock_fix.py` | **同步 9 个锁定文件**：改过就得重算 json 里的 sha256，一条命令搞定 |
| `vmos_meta_fix.py` | **只拨元数据**：把 mode/uid/gid/mtime 改回原包，数据区一个字节不动 |
| `vmos_apex_check.py` | **启动失败定位**：检查 `/system/apex`，并用 build-receipt 的 sha256 核对镜像内容 |
| `verify_roundtrip.py` | 往返自检：解包→打包→再解包，逐项比对，判断是否无损 |
| `vmos_db.py` | 旧版打包程序,参考vmos_rom.py |
| `vmos_7z_db.py` | 内置程序,打包为vmos+可识别的格式 |
## 一、官方包长什么样（这是基准）

```
android15_user_20008.7z    959.5 MB
Method = LZMA2:18          ← LZMA2
Solid  = -                 ← 非固实
Blocks = 560               ← 560 个成员 = 560 个独立块
成员   = 560 个
```

结构：

```
├── root/root/          12 个   (.so / vblock / 00000000/ 下 10 个索引文件)
├── root/vendor/        76 个   (.so / vblock / 74 个索引文件)
├── root/system/       451 个   (.so / vblock / 449 个索引文件)
├── system/framework/services.jar        1 个（顶层散文件，不在 root/ 下）
├── baseline-provenance/                 5 个 json 备份
└── 15 个顶层文件
    guestOSInfo  libvmoskernel.so  kernel-plugin-protocol
    build-receipt.json  boot-sidecars.json  a15-plugin-profile.json
    romex-native.json  runtime-artifacts.json  vendor-runtime-artifacts.json
    media-artifacts.json  media-build-receipt.json
    audio-playback-artifacts.json  audio-playback-build.json
    browser-via-artifacts.json  neutral-render-build.json
```

**这 15 个顶层文件 + 5 个 provenance + services.jar 缺任何一个，导入就失败。**
`guestOSInfo` 决定实例显示什么系统、加载哪个内核；`libvmoskernel.so` 就是内核本体。

---

## 二、五个最常见的错

### 错 1：把 zip 直接改名成 `.7z`

我们的打包链 `vmos_rom.py` 产出的是 **zip**。它不能直接塞进 `assets/roms/`。

```
✘ mv rom.zip android15_user_20008.7z        → 魔数是 PK.. 不是 7z..
✘ cp rom.zip assets/roms/xxx.7z             → 同上
```

VMOS 用 lib7z 打开，读到 `PK\x03\x04` 直接失败，提示往往只有一句"导入失败"。

检查工具第一段就能认出来：`✘ 这是 ZIP，不是 7z`。

### 错 2：7z 用了固实压缩

**7z 默认就是固实（`-ms=on`）**，这不是"有人会加"，是不加就一定是。
典型表现：

```
✘ 7z a rom.7z ./*                      → Solid = +   Blocks = 1
✘ 7z a -t7z -mx=9 rom.7z ./*
```

固实块把多个文件压进同一块，`Blocks` 只剩下 1，而官方是 **560 成员 / 560 块**。
VMOS 要单独取 `root/system/.so` 那一个 2.4 GB 的文件，固实下得先把整块解完才能定位，
结果就是超时或读失败。

**必须 `-ms=off`**。检查器会明确报：

```
✘ 固实压缩（Solid = +）
✘ 块数 1 < 成员数 560，说明多个文件压进了同一块
```

### 错 3：7z 23+ 自动挂了 ARM64 过滤器

7-Zip 从 **23.00** 起，对 ARM64 的 `.so` 会自动套一层 ARM64 BCJ 过滤器，出包头部变成：

```
Method = ARM64 LZMA2:18        ← 官方是纯 LZMA2:18
```

体积只小一点点，但手机里 VMOS 用的 lib7z 多是老版 p7zip（16.02 一类），**不认识这个
过滤器**，解压时报 `Unsupported method`，导入照样失败。而且这个坑很隐蔽：不报错、
不看 Method 根本发现不了。

**必须 `-mf=off` 关掉**。注意光写 `-m0=lzma2` 不够，实测仍会挂 ARM64，必须两个一起：

```bash
7z a -t7z -mx=5 -m0=lzma2 -mf=off -md=256k -ms=off rom.7z @list.txt
```

### 错 4：多了一层目录

```
✘ 7z a rom.7z build/          → 包内变成 build/root/system/.so
✘ 7z a rom.7z stage/          → 包内变成 stage/root/system/.so
```

VMOS 在**包根目录**找 `root/` 和 `guestOSInfo`，多一层就全找不到。

必须在解包目录**里面**用 `./*` 打包。

### 错 5：7z 里带了目录条目

官方 560 个成员**全是文件**，没有 `root/`、`root/system/`、`root/vendor/lib64/` 这类目录条目。

`7z a rom.7z root/` 会自动补进 11~23 个目录条目。多数解压器无害，但 VMOS 的
lib7z 是按成员遍历的，遇到目录条目可能当成待解压的条目处理。

想手动打就只列文件：

```bash
find . -type f | sed 's|^\./||' > /tmp/list.txt
7z a -t7z -mx=5 -m0=lzma2 -mf=off -md=256k -ms=off ../rom_new.7z @/tmp/list.txt
```

`vmos_rom.py --7z` 现在已经这么做了（2026.10.31.3 起）。

---

### ① 解包官方 7z

```bash
python3 vmos_auto.py 官方/android15_user_20008.7z -o rom/
```

### ② 改内容

只动 `rom/system/`、`rom/vendor/`、`rom/root/` 里的文件。
不要碰 `_links.tsv`、`_recovered/`、`*_manifest.*`。

### ③ 直接打成 7z

```bash
python3 vmos_rom.py 官方/android15_user_20008.7z rom/ \
    -o build/rom_new.7z --7z-level 5
```

**输出后缀写 `.7z` 就直接产出 7z**，内部执行的是：

```
cwd = 解包目录
7z a -t7z -mx=5 -ms=off out.7z <所有顶层项>
```

`-ms=off` 是默认行为（除非你显式加 `--7z-solid`），打包在解包目录内完成，
所以不会有 `stage/` 这种多余层级。

> **`--7z-level 5` 一定要加。** 默认是 `0`（不压缩，只为快速验证），
> 打出来 2.7 GB，比官方的 959 MB 大两倍多，实例创建时解压也慢。
> `5` 是官方那种压缩率，`9` 更小但慢一倍。

如果你手上已经是一个 zip（或者一个固实压过的 7z），用这个转：

```bash
python3 vmos_7z_db.py build/rom.zip -o build/rom_new.7z
```

它一条命令做完全部：解压 → 只把文件列进 listfile → `-ms=off -mf=off` 打包 →
逐成员比对大小和 CRC32 → 最后调 `vmos_7z_check.py` 打印【2】【6】结论。

不用再手敲 `mkdir stage && unzip && 7z a ./*` 那一套，也不会漏开关。

### ④ 自检结构

```bash
python3 vmos_7z_check.py build/rom_new.7z --baseline 官方/android15_user_20008.7z
```

要求：

```
✔ 真 7z                        ✔ 非固实（每成员独立块）
✔ 15 个顶层文件齐全              ✔ baseline-provenance 5 个齐全
✔ 三个分区 .so / vblock / 索引分片都在
✔ 官方成员一个不少
```

### ⑤ 算 sha256 和 size

```bash
sha256sum build/rom_new.7z
stat -c %s build/rom_new.7z
```

### ⑥ 改 catalog.json 里的对应条目

`assets/roms/catalog.json` 里 `id` 为 `android15_user_20008` 的那一条：

| 字段 | 改成 | 说明 |
|---|---|---|
| `sha256` | 第 ⑤ 步算出的值 | **必改**，不改就报 "changed or not authorized" |
| `sizeBytes` | 第 ⑤ 步算出的字节数 | **必改** |
| `assetPath` | `roms/你的文件名.7z` | 改了文件名才需要动 |
| `romVersion` | **别动** | 有范围校验，动了报 "out of range" |
| `id` / `name` / `androidVersion` | **别动** | 和引擎、插件下发绑定 |

改完检查合法性：

```bash
python3 -c "import json;json.load(open('catalog.json'));print('JSON OK')"
```

### ⑦ 替换进 APK

```bash
python3 - <<'EOF'
import zipfile
src, dst = '官方.apk', '内置.apk'
new_rom  = 'build/rom_new.7z'
new_json = 'catalog.json'          # 改好的那份
rom_name = 'assets/roms/android15_user_20008.7z'
with zipfile.ZipFile(src) as zin, \
     zipfile.ZipFile(dst, 'w', zipfile.ZIP_STORED, allowZip64=True) as zout:
    for i in zin.infolist():
        if i.filename == rom_name:
            zout.writestr(i, open(new_rom, 'rb').read())
        elif i.filename == 'assets/roms/catalog.json':
            zout.writestr(i, open(new_json, 'rb').read())
        else:
            zout.writestr(i, zin.read(i))
EOF
```

> 7z 本身已经压过，用 `ZIP_STORED` 存进 APK 才不会二次压缩浪费几分钟。
> 官方包也是这么做的（`assets/roms/*.7z` 全是 STORED）。

### ⑧ 重签

```bash
./resign.sh 内置.apk 最终.apk
```

### ⑨ 装

```bash
adb uninstall com.vmos.plus
adb install -r 最终.apk
```

---

## 四、如果 7z 结构全绿还是导入失败

那就是 ② 或 ③ 层。按顺序查：

**① catalog 的 sha256**

```bash
python3 vmos_apk_check.py 最终.apk          # 不带 --no-deep
```

它会同时算 APK 内 7z 的实际 sha256 和 catalog 声明值。不一致就是这里。

**② 9 个锁定文件**

如果你改的文件正好命中这 9 个，包内的 sha256 也得同步，否则导入/启动都会失败：

| 来源 | 文件 |
|---|---|
| `boot-sidecars.json` | 3 个 `libEGL/libGLESv1_CM/libGLESv2_vkhw.so`、`gralloc.vkhw.so`、`libvmos_memtag_off.so`、`heapprofd_client_api.vmos_stub.so` |
| `a15-plugin-profile.json` | `root/init.vmos-plugins.rc`、`root/init.superuser.rc`、`root/system/bin/vmos_plugin_dispatcher` |

```bash
python3 vmos_lock_fix.py 最终.apk --write
```

**③ 镜像本身**

```bash
python3 vmos_rom_diff.py 官方/android15_user_20008.7z build/rom_new.7z
```

要求"记录表 / 索引 / vblock / 锁定文件"四段全绿。