# Part 4 — v0.3 Final Dual-Track Re-eval (Conservative, per audit)

## 范围（按 v0.3 审计决定）

- **多轮良性 40 条作废**（捷径体检：audit/security 词面 gap 1.15 近完美区分，对读文本环节是现成捷径，标注兜不住）。**多轮 = 恶意侧 only，不报良性 FP。**
- 单轮 on-target holdout（161 mal + 31 ben，含从 train partition 的 17 条），良性侧给 bootstrap CI。
- 全程连续信号 AUC（tier0_margin / tier1_prob），无离散序数编码。
- v0.3 分层融合规则（Part 1 gating）是活跃的 pipeline._decide。
- off-target 作对照，不进结论。

## TRACK 2 — 多轮（恶意侧 only，良性已退役）

51 条恶意多轮，205 个前缀（全恶意，AUC 无定义 → 报检出分布）：

| 信号 | 值 |
|------|-----|
| Tier1 prob mean / median | 0.944 / 0.999 |
| 前缀 %prob≥0.5 | **95.1%** |
| 前缀 %prob≥0.4 | 95.6% |
| Tier0 margin mean（−=malicious）| +0.076（偏 benign）|
| Tier0 %margin<0（mal-leaning）| **0.0%** |

**诚实解读**：多轮恶意检出靠 **Tier1 轨迹特征**（前缀级 95.1% prob≥0.5，强）。Tier0 向量检索在多轮上弱（margin 偏 benign，0% 倾向 malicious）——印证 v0.1 发现：多轮靠轨迹，单轮靠向量。但因无合规良性对照，**多轮良性 FP 无法报**（红线修复的绝对数值见 Part 1 caveat，不在此作结论）。

## TRACK 1 — 单轮 on-target（真 holdout）vs off-target（对照）

| 集 | n | tier1 AUC [CI] | tier0 AUC [CI] | hard-block recall | benign hard-FP [CI] |
|----|---|----------------|----------------|-------------------|---------------------|
| **on-target (161mal+31ben)** | 192 | **0.4696** [0.37,0.57] | 0.9980 [0.99,1.00] | **56.5%** | 0.0% [0.00,0.11] |
| off-target test_indist | 275 | 0.8475 [0.79,0.90] | 0.9821 [0.97,0.99] | 88.8% | 0.0% [0.00,0.07] |
| off-target aug_holdout | 842 | 0.5344 [0.45,0.62] | 0.9310 [0.87,0.98] | 53.3% | 6.1% [0.01,0.17] |

## 本轮基线结论（诚实，作为 v0.3 基线，后续以此为准）

### 1. off-target 把单轮能力虚高了 32 个百分点
- on-target hard-block recall **56.5%** vs off-target test_indist **88.8%** → **虚高 32.3pp（绝对）**
- on-target tier1 AUC **0.4696**（近随机，CI[0.37,0.57] 跨 0.5）vs off-target 0.8475 → **虚高 0.38**
- v0.2 的"pipeline 0.97"测的是"识别造炸弹/色情/仇恨"，不是 agent action-risk。**on-target 才是真实基线。**

### 2. Tier1 在单轮 on-target 上近随机（AUC 0.47）
Tier1 XGBoost 的轨迹特征在单轮上退化（v0.1 已发现）。on-target tier1 AUC 0.4696 证实：**Tier1 对单轮 agent-action-risk 几乎无判别力**。单轮靠的是 Tier0 向量检索（AUC 0.9980 on-target）。

### 3. 两层分工确认（与 v0.2 一致，但现在在 on-target 上成立）
- **单轮**：Tier0 向量检索扛（on-target AUC 0.998），Tier1 近随机
- **多轮**：Tier1 轨迹特征扛（95.1% prob≥0.5），Tier0 向量弱（margin 偏 benign）
- 分层融合 gating（Part 1）让两层各管一头，逻辑成立

### 4. 良性误拦：on-target 0%（但 n=31 薄，CI [0,11.3%]）
on-target 单轮良性 hard-FP=0%（CI 上界 11.3%）。n=31 偏薄，CI 宽，不能当"良性 FP 已解决"。但 0% 方向是好的。

## 与 v0.2 的对比（明确"虚高 vs 真实"）

| 指标 | v0.2 报的（off-target）| v0.3 on-target 真实 | 差距 |
|------|----------------------|---------------------|------|
| 单轮 hard-block recall | 88.3% (test_indist) | 56.5% | 虚高 32pp |
| 单轮 tier1 AUC | 0.8420 | 0.4696 | 虚高 0.37 |
| 多轮 AUC | 0.90（含手写良性）| 95.1% prob≥0.5（恶意only）| 不可比（良性退役）|

**后续以 on-target 真实数字为准，不再引用 off-target 虚高数字。**

## 诚实局限

- 多轮良性退役 → 多轮良性 FP / gating 的绝对数值无法在合规数据验证（Part 1 caveat 已记）
- 单轮良性 n=31 偏薄 → 良性指标 CI 宽，方向性参考
- 51 条多轮恶意仍小 → 检出 95.1% 是初步
- Tier2 暂缓（词面红利核查：本质敏感词检测器，非语义判官）

## v0.3 一句话总结

**真实基线**：单轮 on-target hard-block recall 56.5%（off-target 虚高 32pp）；多轮恶意检出 95.1%（靠 Tier1 轨迹）；Tier0 扛单轮、Tier1 扛多轮的分工在 on-target 上成立；Tier1 单轮近随机是当前真实短板；多轮良性 + Tier2 都因数据/能力问题暂缓，不投入实现。
