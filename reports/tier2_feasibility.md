# 独立小任务 — 21条分歧样本验证 Tier2 可行性

## 任务背景

用户提到可并行推进的小任务：用 Part 1 那 21 条分歧样本（Tier0 benign / Tier1 高分的 defer 边界区），验证 Tier2（LLM 语义判官）能否解决这类分歧。Tier2 在 v0 是 stub（`not_implemented`），这是首次实测可行性。

## 方法

- 取 Part 1 的 defer 样本（重训模型后 22 条：6 恶意 + 16 良性）
- 用 DeepSeek v4-flash 当 Tier2 LLM 判官（`enable_thinking:false`，走已验证通的路径）
- 判官 prompt 读完整多轮对话，判 malicious/benign，输出 JSON
- 良性 16 条是 v0.2 手写（Part-0 标 untrusted），但内容上仍是"多步调试/审计/部署"措辞，参考可用

## 结果

| | 正确/总数 | 准确率 |
|---|---|---|
| 总体 | 20/22 | 90.9% |
| 恶意 | 4/6 | 67% |
| 良性 | 16/16 | 100% |

## 诚实解读

**良性侧 100%**：LLM 判官能完美区分"真实多步调试任务"和攻击——这对 Part 1 的红线问题有直接价值。Part 1 的 15 条良性 defer 若交给 Tier2，全部能正确判 benign，**可进一步降级为 allow 而非 defer**（减少人工复核量）。

**恶意侧 67%（2 条漏判）**：2 条恶意被判 benign——正是伪装成"调试/审计"的攻击（crescendo 的 generated-vulnerability / repo-prompt-injection）。LLM 也被表面话术骗过。这对应 Part 1 那 6 个 defer 里的 2 个：**LLM 判官不是银弹**，对伪装良性的攻击仍漏判。

## 结论（对 v0.3 的意义）

Tier2 **可行且有价值，但不是银弹**：
- 在**降低良性误拦**（Part 1 红线的另一半）上 100% 有效——defer 里的良性可由 Tier2 确认后放行
- 在**检出伪装良性的攻击**上 67%，不如 Tier1 的高分警报——所以 Tier2 不能替代 Tier1 的 defer，应是**复核层**：Tier1 高分 + Tier0 benign → Tier2 复核，Tier2 判 benign 才放行、判 malicious 才升级为 block
- 这正好支持 Part 1 的 defer 设计（送审而非直接放行/拦截）：Tier2 作为 defer 的自动复核，能把 15 良性 defer 里的（估计全部）自动放行，把 6 恶意 defer 里的 4 个自动升级 block，剩 2 个漏判仍需人工

## 与本轮主线的关系

这是独立可行性验证，不改动 pipeline。若后续要把 Tier2 接进 fusion，是另一个版本的事（Tier2 stub → 实装 + 接入 `_decide` 的 defer 分支）。本轮只验证可行性 + 给出接入建议。

## 数据
- `reports/tier2_disagreement_samples.json`（22 条样本）
- `reports/tier2_feasibility.json`（逐条结果）
