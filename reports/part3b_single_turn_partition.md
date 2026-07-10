# Part 3(b) — 单轮良性 partition + 泄漏检查（全过程记录，非一句话）

## 批准的操作

从 train 切 ~17 条 AgentDojo benign 到 on-target holdout（partition，非生成，Part-0 合规）。

## 泄漏检查过程（动手前做的，不是事后补的）

### 检查 1：要移动的记录是否参与过 `build_benign_profile` 拟合？

`novelty_recipient`/`novelty_filepath` 两个特征依赖的良性参考画像，由 `build_benign_profile` 扫描**全部 benign 训练记录**生成。查 `train.py` + `build_benign_profile`：

- profile 输入 = train.jsonl + xgboost_paper_derived.jsonl + promptfoo_redteam.jsonl 的**所有 benign 记录**（共 3599 条：77 AgentDojo + 310 hf_deepset + 12 near_dup + 3200 synth）
- **77 条 AgentDojo benign 参与了 profile 拟合**
- profile 输出：2 recipients（`sarah.connor@gmail.com`、`david.smith@bluesparrowtech.com`）+ 22 filepaths
- 逐条核查 AgentDojo benign 对 profile 的**实际贡献**：
  - 贡献了 **2 个 recipients**（全部 2 个都来自 AgentDojo benign）
  - 贡献了 **0 个 filepaths**

**结论 1**：要移动的 17 条 AgentDojo benign **确实参与过 profile 拟合**（它们在 train 的 77 条里）。所以不能直接用"见过它们"的旧 profile 测 holdout。

### 检查 2：那 2 个 recipient 的记录会不会被移走？

- 要移动的 17 条（按 id 排序取后 17）：**不含**那 2 个 recipient 的记录
- 那 2 个 recipient 的记录**留在 train**（在 keep 的 60 条里）

**结论 2**：重新拟合后 profile 仍能学到这 2 个 recipient，内容不丢失。

### 检查 3：连锁泄漏 — Tier1 模型本身见过这 17 条

`xgboost_full.json` 用旧 399 benign 训练，**模型特征层面见过这 17 条**。这是 profile 之外的第二层泄漏。处理：用新 train（2132，benign 382）**重训模型**。

## 执行

1. 备份 `train.jsonl` → `train.jsonl.v03pre_bak`
2. `partition_benign_to_holdout.py`：train 2149→2132（benign 399→382）；on-target holdout 161 mal + 31 ben = 192（train-id 泄漏=0）
3. 重新拟合 profile（基于 382 benign，排除 holdout 31 条）→ 与旧 profile **完全一致**（2 recipients + 22 filepaths，集合相等）→ 泄漏消除、内容不丢
4. 用新 train 重训 `xgboost_full.json`（模型层泄漏消除）

## 验证

| 指标 | 旧 | 新 |
|------|----|----|
| train benign | 399 | 382 |
| profile recipients | 2 | 2（一致）|
| profile filepaths | 22 | 22（一致）|
| on-target holdout benign | 14 | 31 |
| holdout train-id 泄漏 | 0 | 0 |
| 127 测试 | pass | pass |

## 依据记录（不只"已排查没问题"）

- profile 输入来源：`build_benign_profile(benign_records)`，`benign_records` 来自 `train_all` 的 `is_malicious is False`（见 train.py L80-83）
- AgentDojo benign 对 profile 的实际贡献：逐条重跑 `_RE_RECIPIENT`/`_RE_FILEPATH` 提取后比对 profile 集合（代码可复现，见检查脚本）
- 移动记录不含 2 个 recipient 记录：按 id 排序取后 17 条，逐条 grep recipient 确认

## 仍未消除的限制（诚实）

即便补到 31 条，单轮良性样本量仍偏薄。Part 4 这部分指标**必须给 bootstrap 置信区间**，不因补了几条省略。

## 文件
- `dataset/scripts/partition_benign_to_holdout.py`（partition 实现）
- `dataset/processed/train.jsonl.v03pre_bak`（备份）
- `dataset/reports/part3b_moved_ids.json`（移动的 17 条 id，可追溯）
