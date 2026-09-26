# Erratum — IP-0027 Packet §7.3.1 fingerprint transcription error

> 文档类型：勘误记录（Erratum）· 版本 v1.0 · 日期 2026-09-26
>
> 关联：Issue #212（SR-IP-0027-01 纠偏）、IP-0027、PR #213
>
> 授权：MAINTAINER_AUTHORIZED（2026-09-26 长程授权第二节：对 Packet 指纹笔误建立可追溯勘误）

## 1. 勘误对象

`docs/LIMA_Implementation_Packet_IP-0027_Baseline_Collection_Foundation.md` §7.3.1 表格中 `lima-real-world-pilot-v1` 行的 fingerprint。

## 2. 三方核验事实（2026-09-26 程序化核验，可复现）

| 来源 | 值 | 长度 | 判定 |
|---|---|---:|---|
| 冻结真值 `evaluation_data/v4/baseline_manifest.json`（`real_world_security_cases.json` 字节 SHA-256） | `7d88728caca8bc3387802b7bdaa09b59e5ffe1fede21a71c3d314bd63eb0c106` | 64 | 真值 |
| Packet §7.3.1（C1 `81d9beded321adc3383dfbc8615ed4a3b73f51b0` 至 merge `abd9d025` 的 main） | `7d88728caca8bc3387802b7bdaa09b59e5ffe1ede21a71c3d314bd63eb0c106` | 63 | **笔误**：第 38 位（0 基）脱落一个 `f` |
| 实现 `benchmarks/v4/baseline/run.py::FROZEN_DATASET_BINDINGS`（merge 后 main 实测） | 与真值逐字相等（三条 dataset 指纹全部 verbatim 命中） | 64 | 正确 |

核验方法：`regex [0-9a-f]{63}` 在 Packet 全文恰命中 1 处（offset 20751）；真值 64 字符串在 Packet 出现 0 次；`git cat-file -p <blob>` 复核。git blob ID（Packet @ main = `eb4ed525…`）与文件内容 SHA-256 是两种不同哈希体系，本文不混称。

## 3. 责任与成因

P&V 起草 Packet §7.3.1 时人工转写脱落一个字符（Coordinator Assignment R2 的三条指纹本身全部正确；非同源）。已在 P&V Verification Report Finding 1 如实自报，Evidence Review ERR-IP-0027-v1 第 14 项程序化复核属实。

## 4. 影响评估

**无实现/验收影响**：Packet 同段明文声明真值来源为 manifest 逐字转录（DI-009/R2）；冻结测试 `tests/test_v4_baseline_collection.py` 以 manifest 为 oracle 强制 `registry == manifest`（26/26 绿）；实现注册表经三方核验与真值逐字相等。缺陷仅存在于 Packet 文档文本。

## 5. 处置

1. 本勘误文件入库（可追溯记录）。
2. 随同本 PR 对 Packet §7.3.1 该行做最小修正（63 → 64 字符，恢复与真值逐字一致）；不改变任何其他内容、产品语义或冻结测试。
3. 历史保留：C1 Frozen Packet 的历史 SHA（commit `81d9beded321adc3383dfbc8615ed4a3b73f51b0`，blob 沿 git 历史可达）不改写、不删除；本勘误不回写历史。
4. 流程教训（登记）：Packet 等规格文档中引用哈希真值必须程序化复制粘贴，禁止人工转写。
