# 面试快速参考卡片 - 面试前30分钟速览

---

## 一句话项目定位（背下来）

> SecureAI Toolkit 是一个覆盖"AI赋能安全"和"AI自身安全"两大方向的安全攻防工具集，
> 包含4个核心模块：CTF自动解题器、LLM安全测试框架、AI威胁检测引擎、对抗样本攻防实验室。

---

## 项目架构速记

```
SecureAI Toolkit
├── CTF-AutoSolver    [AI赋能安全]  ReAct Agent + Function Calling
├── LLM-Guard         [AI自身安全]  Prompt Injection / Jailbreak 攻防
├── ThreatLens        [AI赋能安全]  ML威胁检测 + LLM辅助
└── AdverLab          [AI自身安全]  FGSM/PGD/C&W 攻防实验
```
技术栈: Python + FastAPI + React + PyTorch + OpenAI/Ollama + LightGBM + Docker

---

## 四个模块一句话定位

| 模块 | 一句话 | 对应阿里云业务 |
|------|--------|--------------|
| CTF-AutoSolver | ReAct Agent驱动+8个安全工具的CTF自动解题 | 安全自动化/SOAR |
| LLM-Guard | 6种攻击策略+双层防御管道的LLM安全测试 | 内容安全风控 |
| ThreatLens | 3种检测模型+LLM辅助研判的威胁检测 | 智能安全运营 |
| AdverLab | FGSM/PGD/C&W攻击+对抗训练防御 | 模型鲁棒性评估 |

---

## 高频考点速答

### LLM-Guard (最重点)

**攻击方式**: 直接注入(15模板) + 间接注入(数据/工具/代码) + 多轮注入(3序列)
**Jailbreak**: 模板攻击(8种) + PAIR(迭代优化) + GCG(对抗后缀)
**Jailbreak vs 注入**: 注入=劫持行为(控制权窃取), 越狱=突破约束(边界突破)
**PAIR原理**: 攻击LLM生成prompt -> 目标LLM响应 -> 评估 -> 优化, 5轮迭代, 0.8阈值早停
**防御**: 关键词过滤(<1ms) + LLM过滤(~200ms), 用自己的矛攻自己的盾
**LLM-as-Judge问题**: 位置偏见/自我偏好/verbosity偏见, 应对: 5级评分+JSON强制+关键词回退

### CTF-AutoSolver

**ReAct vs 端到端**: 可解释/可干预/可集成工具
**工具调用**: 注册表模式, OpenAI function calling schema, 15轮迭代上限
**8个工具**: http_request/z3_solve/run_command/pwn_connect/base64编解码/xor/regex
**专用vs通用**: Web/Pwn/Reverse/Crypto有专用解题器(效率+成功率), 通用Agent作fallback

### ThreatLens

**AutoEncoder异常检测**: 仅用正常流量训练, 异常重建误差大, 不需攻击样本, 可检测零日
**3种模型**: AutoEncoder(未知威胁) + LightGBM(已知分类) + CNN1D(特征提取)
**LLM辅助**: 只在检测到异常时调用, 解决长尾+可解释性, 延迟约200ms

### AdverLab

**FGSM**: 单步, x'=x+eps*sign(grad), 快但粗
**PGD**: 多步迭代+投影, 精确但慢
**C&W**: tanh变换优化, L2扰动最小, 最慢
**对抗训练**: PGD生成对抗样本混入训练(mix_ratio=0.5), trade-off: 鲁棒性-准确率悖论(3-5%下降)
**预处理防御**: 位深度缩减/JPEG压缩/高斯噪声/中值滤波, 核心: 破坏对抗扰动精度

---

## 系统设计速答

**线上部署**: 关键词过滤做网关(ms级) + LLM过滤做异步深度审核, F1-score调优
**容错**: 双Provider切换/LLM Judge回退/工具异常捕获/15轮上限
**改进**: RAG增强/多Agent协作/攻防闭环自动化

---

## 节奏控制5要点

1. 开场说"AI赋能安全+AI自身安全", 让面试官选方向
2. 多提"闭环", 引导问模块联动
3. 适时提"这个思路和阿里云XX类似"
4. 每个技术点主动暴露trade-off
5. 用数据说话: FGSM eps=0.03成功率~70%, LLM Judge 5级0-1.0

---

## 关键数字

- 直接注入模板: 15种
- Jailbreak模板: 8种
- 安全工具: 8个
- ReAct迭代上限: 15轮
- PAIR迭代: 5轮
- GCG迭代: 10轮
- 对抗训练混合比: 0.5
- LLM Judge评分: 5级(0-0.2/0.2-0.4/0.4-0.6/0.6-0.8/0.8-1.0)
- 关键词过滤延迟: <1ms
- LLM过滤延迟: ~200ms
- 对抗训练准确率下降: 3-5%
- ThreatLens特征维度: 37维