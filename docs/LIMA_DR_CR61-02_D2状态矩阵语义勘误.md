# DR-CR61-02:静态状态矩阵 D2-only 语义勘误(文档面,零代码变更)

- 编号来源:CRDISP-1 处置表 §1 第 4 行(CR61-02,consumer review #61 回复,
  评论 5559621866);裁定:需要补齐(文档勘误),不阻塞 #58 关闭。
- 对象:`lima/contracts/evidence.py` 静态状态矩阵——`has_d2_supports`/`has_d2_refutes`
  仅统计 D2 等级证据,决定 `HypothesisStatus` 的
  statically_supported / statically_refuted / conflicting_static_evidence /
  insufficient_static_evidence 四值判定。
- 语义澄清(单解):该矩阵为 **D2-only 设计**(IP-0002 冻结面,`207222d`→`31449ee`
  零修改)。D1 及以下等级的反证**不参与**该矩阵判定:混合等级组合
  (如 D2-support + D1-refute)输出 `statically_supported` 是设计行为,非缺陷。
  D1 及以下反证的保留,以及据此向验证层 `inconclusive` 的输出,是 **#61 消费侧义务,
  不经该矩阵表达**。
- 后续约束:若未来需要把混合等级语义编入 wire 矩阵,必须新 major + ADR
  (独立后续 IP,经 Coordinator 批准),禁止原地修改 4.0。
- 证据:evidence.py @`0c560df` L1472-1486(CRDISP-1 亲验)+ 可复现反例
  (D2-support + D1-refute → statically_supported,与代码一致)。
