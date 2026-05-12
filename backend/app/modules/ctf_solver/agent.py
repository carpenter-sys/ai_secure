"""
CTF-AutoSolver - ReAct Agent 核心
基于 ReAct (Reasoning + Acting) 范式的 CTF 解题 Agent
LLM 作为推理核心，调用安全工具执行操作
"""
import json
import logging
import uuid
from datetime import datetime
from typing import Any, AsyncIterator, Optional

from app.core.llm import llm_router
from app.core.tools import tool_registry
from app.models.schemas import (
    CTFCategory,
    CTFChallenge,
    CTFSolveRequest,
    CTFSolution,
    TaskStatus,
)

logger = logging.getLogger(__name__)

# ReAct Agent 的系统提示词模板
SYSTEM_PROMPT_TEMPLATE = """You are an expert CTF (Capture The Flag) security challenge solver. You have deep knowledge in:

- **Web Security**: SQL injection, XSS, CSRF, SSRF, file inclusion, command injection, authentication bypass
- **Binary Exploitation (Pwn)**: Buffer overflow, ROP chains, format string vulnerabilities, heap exploitation
- **Reverse Engineering**: Disassembly analysis, deobfuscation, algorithm recovery
- **Cryptography**: Classical ciphers, RSA attacks, block cipher analysis, hash collisions
- **Forensics & Misc**: File analysis, steganography, network forensics, OSINT

You solve challenges using the ReAct (Reasoning + Acting) approach:
1. **Thought**: Analyze the challenge and plan your approach
2. **Action**: Use available tools to gather information or test hypotheses
3. **Observation**: Review tool results and refine your understanding
4. Repeat until you find the flag or exhaust all approaches

**Current Challenge**:
- Title: {title}
- Category: {category}
- Description: {description}
- URL: {url}

**Available Tools**: {tools}

**Important Rules**:
- Always explain your reasoning before taking actions
- Start with reconnaissance/information gathering
- Try the simplest approach first before complex exploits
- If an approach fails, analyze why and try an alternative
- When you find the flag, format it clearly as: FLAG{{...}}
- Be thorough but efficient - avoid unnecessary repetitive actions
"""

MAX_ITERATIONS = 15


class CTFAgent:
    """CTF 解题 ReAct Agent"""

    def __init__(self, provider: str = "openai"):
        self.provider = provider
        self.conversation: list[dict[str, str]] = []
        self.tools_used: list[str] = []
        self.steps: list[dict[str, Any]] = []

    def _build_system_prompt(self, challenge: CTFChallenge) -> str:
        tools_desc = ", ".join(
            f"{t['name']}: {t['description']}"
            for t in tool_registry.list_tools()
        )
        return SYSTEM_PROMPT_TEMPLATE.format(
            title=challenge.title,
            category=challenge.category.value,
            description=challenge.description,
            url=challenge.url or "N/A",
            tools=tools_desc,
        )

    async def solve(self, challenge: CTFChallenge) -> CTFSolution:
        """
        使用 ReAct 循环自动解题
        """
        self.conversation = [
            {"role": "system", "content": self._build_system_prompt(challenge)},
            {"role": "user", "content": f"Please solve this {challenge.category.value} CTF challenge. Start by analyzing the description and planning your approach."},
        ]

        flag = None
        for iteration in range(MAX_ITERATIONS):
            logger.info(f"[CTF Agent] Iteration {iteration + 1}/{MAX_ITERATIONS}")

            try:
                # 调用 LLM（带工具定义）
                tools_schema = tool_registry.get_openai_tools_schema()
                result = await llm_router.chat_with_tools(
                    messages=self.conversation,
                    tools=tools_schema,
                    provider=self.provider,
                    temperature=0.3,
                )

                # 记录 LLM 的思考
                assistant_content = result.get("content", "")
                tool_calls = result.get("tool_calls", [])

                # 添加助手消息到对话
                assistant_msg: dict[str, Any] = {"role": "assistant"}
                if assistant_content:
                    assistant_msg["content"] = assistant_content
                    self.steps.append({
                        "iteration": iteration + 1,
                        "type": "reasoning",
                        "content": assistant_content,
                    })
                    logger.info(f"[CTF Agent] Thought: {assistant_content[:200]}")

                if tool_calls:
                    assistant_msg["tool_calls"] = [
                        {
                            "id": tc["id"],
                            "type": "function",
                            "function": {
                                "name": tc["name"],
                                "arguments": tc["arguments"],
                            },
                        }
                        for tc in tool_calls
                    ]
                    self.conversation.append(assistant_msg)

                    # 执行每个工具调用
                    for tc in tool_calls:
                        tool_name = tc["name"]
                        tool_args = json.loads(tc["arguments"]) if isinstance(tc["arguments"], str) else tc["arguments"]

                        logger.info(f"[CTF Agent] Action: {tool_name}({tool_args})")
                        self.tools_used.append(tool_name)

                        # 执行工具
                        observation = await tool_registry.execute_tool(tool_name, tool_args)

                        # 添加工具结果到对话
                        self.conversation.append({
                            "role": "tool",
                            "tool_call_id": tc["id"],
                            "content": observation,
                        })

                        self.steps.append({
                            "iteration": iteration + 1,
                            "type": "action",
                            "tool": tool_name,
                            "arguments": tool_args,
                            "observation": observation[:500],
                        })

                        # 检查是否找到 flag
                        flag = self._extract_flag(observation)
                        if flag:
                            logger.info(f"[CTF Agent] Flag found: {flag}")
                            break
                else:
                    # 没有工具调用，纯文本回复
                    self.conversation.append(assistant_msg)
                    # 检查回复中是否有 flag
                    if assistant_content:
                        flag = self._extract_flag(assistant_content)
                        if flag:
                            break

            except Exception as e:
                logger.error(f"[CTF Agent] Error in iteration {iteration + 1}: {e}")
                self.steps.append({
                    "iteration": iteration + 1,
                    "type": "error",
                    "content": str(e),
                })

        # 生成最终分析总结
        final_analysis = await self._generate_summary(challenge, flag)

        return CTFSolution(
            challenge_id=challenge.id or str(uuid.uuid4()),
            category=challenge.category,
            analysis=final_analysis,
            strategy=self._extract_strategy(),
            payload=self._extract_payload(),
            flag=flag,
            tools_used=list(set(self.tools_used)),
            steps=self.steps,
            confidence=self._calculate_confidence(flag),
        )

    async def solve_stream(self, challenge: CTFChallenge) -> AsyncIterator[dict[str, Any]]:
        """
        流式解题，逐步输出 Agent 的思考过程
        """
        self.conversation = [
            {"role": "system", "content": self._build_system_prompt(challenge)},
            {"role": "user", "content": f"Please solve this {challenge.category.value} CTF challenge."},
        ]

        yield {"type": "start", "challenge": challenge.title}

        for iteration in range(MAX_ITERATIONS):
            try:
                tools_schema = tool_registry.get_openai_tools_schema()
                result = await llm_router.chat_with_tools(
                    messages=self.conversation,
                    tools=tools_schema,
                    provider=self.provider,
                    temperature=0.3,
                )

                assistant_content = result.get("content", "")
                tool_calls = result.get("tool_calls", [])

                if assistant_content:
                    yield {
                        "type": "reasoning",
                        "iteration": iteration + 1,
                        "content": assistant_content,
                    }

                if tool_calls:
                    self.conversation.append({
                        "role": "assistant",
                        "content": assistant_content,
                        "tool_calls": [
                            {
                                "id": tc["id"],
                                "type": "function",
                                "function": {
                                    "name": tc["name"],
                                    "arguments": tc["arguments"],
                                },
                            }
                            for tc in tool_calls
                        ],
                    })

                    for tc in tool_calls:
                        tool_name = tc["name"]
                        tool_args = json.loads(tc["arguments"]) if isinstance(tc["arguments"], str) else tc["arguments"]

                        yield {
                            "type": "action",
                            "iteration": iteration + 1,
                            "tool": tool_name,
                            "arguments": tool_args,
                        }

                        observation = await tool_registry.execute_tool(tool_name, tool_args)

                        self.conversation.append({
                            "role": "tool",
                            "tool_call_id": tc["id"],
                            "content": observation,
                        })

                        yield {
                            "type": "observation",
                            "iteration": iteration + 1,
                            "content": observation[:2000],
                        }

                        flag = self._extract_flag(observation)
                        if flag:
                            yield {"type": "flag_found", "flag": flag}
                            return
                else:
                    self.conversation.append({"role": "assistant", "content": assistant_content})
                    if assistant_content:
                        flag = self._extract_flag(assistant_content)
                        if flag:
                            yield {"type": "flag_found", "flag": flag}
                            return

            except Exception as e:
                yield {"type": "error", "iteration": iteration + 1, "content": str(e)}

        yield {"type": "max_iterations_reached"}

    def _extract_flag(self, text: str) -> Optional[str]:
        """从文本中提取 flag"""
        import re
        # 常见 flag 格式
        patterns = [
            r"flag\{[^}]+\}",
            r"FLAG\{[^}]+\}",
            r"ctf\{[^}]+\}",
            r"CTF\{[^}]+\}",
            r"[a-zA-Z0-9_]+\{[^}]+\}",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(0)
        return None

    def _extract_strategy(self) -> str:
        """从步骤中提取解题策略"""
        reasoning_steps = [s for s in self.steps if s.get("type") == "reasoning"]
        if reasoning_steps:
            return reasoning_steps[0].get("content", "")[:500]
        return "No strategy extracted"

    def _extract_payload(self) -> Optional[str]:
        """从步骤中提取关键 payload"""
        action_steps = [s for s in self.steps if s.get("type") == "action"]
        for step in action_steps:
            args = step.get("arguments", {})
            if "payload" in args:
                return args["payload"]
            if "command" in args:
                return args["command"]
            if "body" in args:
                return args["body"]
        return None

    async def _generate_summary(self, challenge: CTFChallenge, flag: Optional[str]) -> str:
        """生成最终分析总结"""
        summary_prompt = (
            f"Summarize the CTF challenge solving process in a concise report.\n"
            f"Challenge: {challenge.title} ({challenge.category.value})\n"
            f"Flag found: {'Yes - ' + flag if flag else 'No'}\n"
            f"Steps taken: {len(self.steps)}\n"
            f"Tools used: {', '.join(set(self.tools_used))}\n"
            f"Provide a brief technical summary of the vulnerability and solution."
        )
        try:
            return await llm_router.chat(
                messages=[
                    {"role": "system", "content": "You are a CTF solution summarizer. Provide concise, technical summaries."},
                    {"role": "user", "content": summary_prompt},
                ],
                provider=self.provider,
                temperature=0.3,
                max_tokens=1000,
            )
        except Exception:
            return f"Solving process completed with {len(self.steps)} iterations. Flag: {flag or 'Not found'}."

    def _calculate_confidence(self, flag: Optional[str]) -> float:
        """计算解题置信度"""
        if flag:
            return 0.95
        reasoning_count = len([s for s in self.steps if s.get("type") == "reasoning"])
        action_count = len([s for s in self.steps if s.get("type") == "action"])
        if action_count > 0:
            return min(0.5, action_count * 0.1)
        if reasoning_count > 0:
            return 0.2
        return 0.0