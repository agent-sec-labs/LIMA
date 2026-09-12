# ADR 0027:契约版本兼容策略与 schemas/v4 快照

- 状态:Accepted(冻结决策的记录,不新增决策)
- 日期:2026-09-06
- 关联:#58(FR-06)、IP-0001..IP-0010、`schemas/v4/`、`schemas/v4/version_compatibility_matrix.json`

## 背景

LIMA 跨阶段 Artifact 契约(v4 wire)由九个模块承载,版本兼容行为自 IP-0001 起逐 IP 冻结。
IP-0010 将这些**既有冻结决策**导出为 PR3 类 artifact(JSON Schema 文件 + 版本兼容矩阵 +
本 ADR),供下游仅依赖静态工件并行开发。本 ADR 只记录已生效决策,不引入新语义。

## 决策记录

1. **未知 major fail-closed**:`SchemaVersion` 拒绝非 4 的 major(`SCHEMA_UNKNOWN_MAJOR`),
   永不猜测降级(IP-0001 §9;#58 NFR-01)。
2. **current minor(4.0)unknown field 拒绝**:任意层级的未知字段在 4.0 被拒绝
   (`UNKNOWN_FIELD`);这是导出 schema 文件 `additionalProperties: false`(顶层)的依据。
3. **future minor(4.x)extension 无损 round-trip**:同 major 未来 minor 的未知字段经
   `extensions` 机制保留往返;这是**模块级行为**,单一静态 2020-12 schema 不做版本条件化
   表达——schema 文件始终描述 current minor 的结构面,future-minor 容忍度记录于兼容矩阵
   (locus = module)。
4. **required 缺失与 unknown enum 永不降级**:任何 minor 下均拒绝
   (`REQUIRED_FIELD_MISSING` / `UNKNOWN_ENUM_VALUE`)。
5. **major bump 政策**:仅当 wire 出现破坏性变更时启用新 major;破坏性建议一律记录为
   新 major 而非原地修改(#58 Done 条款;历次 Packet Rejected Inputs 一贯拒绝原地改
   冻结面)。
6. **schemas/v4 快照语义**:`schemas/v4/*.json` 是 4.0 结构面的**机械快照**(从冻结 wire
   契约推导;生成期经运行时探针自证),不构成第二真值源——语义真值源仍是九模块;
   一致性测试机器断言快照与运行时零漂移(required 集合 = 删除探针;enum = 模块枚举全表;
   golden payload 通过 schema 校验)。
7. **跨字段不变量与嵌套对象**:mode⇒inputs 双射、AUDIT_ONLY 排除、revision⇔supersedes
   耦合、有序/排序数组、inline XOR blob 等不在 schema 文件中表达(2020-12 单文件静态
   表达会制造第二份跨字段逻辑);其执行位置(locus)逐条记录于兼容矩阵。

## 后果

- 下游可仅凭 `schemas/v4/` + 矩阵做静态集成;语义疑问以模块与矩阵 locus 为准。
- 每次 minor 演进需同步再导出快照(v4.x 目录或原地更新由当时的 IP 冻结)。
