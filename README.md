# VMOS Plus Rom解包工具
## 使用方法：
```bash
解包: python3 vmos_auto.py rom.7z
打包: python3 vmos_db.py 原包.7z ./vmos_out -o 输出修改.rom
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
