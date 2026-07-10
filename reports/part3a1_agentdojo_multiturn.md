# Part 3(a) 第一条 — AgentDojo 多轮原始数据解析：结构不适用（如实报告）

## 验收标准回顾

> 只有当解析出来的数据，语义上真的对应"用户提出一个多步骤良性任务"时才采用；
> 如果本质上是"工具调用→工具返回结果"这种交替结构、没法自然对应成"用户请求"的语义，
> 就如实报告"AgentDojo 多轮原始结构不适用于我们的场景"，不要强行改写或主观解读。

## 解析过程（拉取了 raw/agentdojo 全仓库）

AgentDojo 的 benchmark 结构（`src/agentdojo/default_suites/v*/`）：
- `user_tasks.py`: 每个 `class UserTaskNN(BaseUserTask)` 有类属性 `PROMPT = "..."`（良性用户指令）
- `injection_tasks.py`: 每个 `class InjectionTaskNN` 有类属性 `GOAL = "..."`（注入目标）
- `BaseUserTask.PROMPT` 基类注释明确：**"The prompt that the model receives"** — 单轮字符串
- `ground_truth()` 返回 `list[FunctionCall]` = **agent 要执行的工具调用序列**（执行端多步）

粗估 raw 共 ~121 个 UserTask.PROMPT。我们 normalize 后得 134 条（91 良性 UserTask + 43 恶意 InjectionTask），与现有记录一致。

## 结构定性（关键）

AgentDojo 的"conversation"是：
```
user prompt (1条单轮) → agent → tool调用 → tool_result → agent → tool → ...
```
**多步性在 agent-tool 执行端，不是用户发多个 prompt。** 不存在"用户提出多步骤良性任务"（多轮 user 指令）的形态。

`full_conversation` 模式（见 `pi_detector.py`）指的是 agent-tool 交互的完整记录，不是 user-user 多步请求。

## 结论：不适用，不强行改写

按验收标准，**AgentDojo 多轮原始结构不适用于我们的"用户多步良性请求"场景**。

强行把 `ground_truth()` 的 `FunctionCall` 序列改写成 user turns = 把"agent 的执行计划"伪装成"用户的请求语义"，这是主观解读，违反验收标准，不做。

## 可诚实利用的部分（不是强行利用）

AgentDojo 的 **单轮** 良性 UserTask.PROMPT（91 条）是最 on-target 的**单轮**良性来源（工具调用任务，比 hf_deepset "什么是美好的"通用 QA 强）。这部分已在 normalize 里（77 在 train，14 不在）。这用于 Part 3(b) 的单轮良性 partition——不是本轮"多轮"需求。

## 数量报告

- 解析出的"用户多步良性任务"多轮记录：**0 条**（结构不匹配，AgentDojo 无此形态）
- 因结构不匹配排除：全部 ~121 个 UserTask（都是单轮 prompt，多步在执行端）

第一条路对"多轮良性"是死的。第二条路（修 promptfoo）是获得合规多轮良性的唯一可行路径。
