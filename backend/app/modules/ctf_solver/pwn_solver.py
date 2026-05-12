"""
CTF-AutoSolver - Pwn 题型专用解题器
针对二进制漏洞利用题目的专项解题逻辑
"""
import logging
from typing import Any, Optional

from app.core.llm import llm_router
from app.core.tools import tool_registry
from app.models.schemas import CTFChallenge, CTFSolution

logger = logging.getLogger(__name__)

PWN_SYSTEM_PROMPT = """You are a Binary Exploitation (Pwn) CTF expert. Analyze and exploit vulnerable binaries.

Common Pwn CTF techniques:
- **Buffer Overflow**: Stack overflow, heap overflow, off-by-one
- **ROP Chains**: ret2libc, ret2csu, ret2plt, SROP
- **Format String**: Information leak, arbitrary write
- **Heap Exploitation**: Use-after-free, double-free, fastbin attack, tcache poisoning
- **Integer Overflow**: Signedness issues, truncation
- **Shellcode**: Custom shellcode, restricted character sets

For each challenge:
1. Identify the vulnerability type
2. Determine protections (NX, ASLR, Canary, PIE)
3. Develop exploitation strategy
4. Craft the exploit payload
5. Get a shell and capture the flag
"""


class PwnSolver:
    """二进制漏洞利用 CTF 解题器"""

    def __init__(self, provider: str = "openai"):
        self.provider = provider
        self.tools_used: list[str] = []
        self.steps: list[dict[str, Any]] = []

    async def solve(self, challenge: CTFChallenge) -> CTFSolution:
        """自动解题"""
        # 分析二进制文件
        binary_info = {}
        if challenge.attachment_paths:
            for path in challenge.attachment_paths:
                # 文件类型和安全机制检查
                file_result = await tool_registry.execute_tool("run_command", {
                    "command": f"file {path} && checksec --file={path} 2>/dev/null",
                })
                self.tools_used.append("run_command")
                binary_info[path] = file_result

        # LLM 分析
        analysis = await llm_router.chat(
            messages=[
                {"role": "system", "content": PWN_SYSTEM_PROMPT},
                {"role": "user", "content": (
                    f"Challenge: {challenge.title}\n"
                    f"Description: {challenge.description}\n"
                    f"URL/Host: {challenge.url or 'N/A'}\n"
                    f"Binary info: {binary_info}\n\n"
                    f"Analyze this pwn challenge:\n"
                    f"1. What vulnerability type is most likely?\n"
                    f"2. What protections are enabled/disabled?\n"
                    f"3. What exploitation strategy should we use?\n"
                    f"4. Provide a pwntools exploit script outline."
                )},
            ],
            provider=self.provider,
            temperature=0.3,
        )

        self.steps.append({
            "step": "analysis",
            "content": analysis[:1000],
        })

        # 尝试自动利用
        flag = None
        if challenge.url:
            # 尝试连接并利用
            host_port = challenge.url.replace("nc ", "").split(":")
            if len(host_port) == 2:
                host, port = host_port[0], int(host_port[1])

                # 让 LLM 生成 exploit 脚本
                exploit_script = await llm_router.chat(
                    messages=[
                        {"role": "system", "content": PWN_SYSTEM_PROMPT},
                        {"role": "user", "content": (
                            f"Generate a complete pwntools exploit script for:\n"
                            f"Host: {host}, Port: {port}\n"
                            f"Analysis: {analysis}\n\n"
                            f"Output ONLY the Python code, no explanations. "
                            f"The script should connect, exploit, and print the flag."
                        )},
                    ],
                    provider=self.provider,
                    temperature=0.3,
                )

                # 尝试执行 exploit
                run_result = await tool_registry.execute_tool("run_command", {
                    "command": f"python3 -c {repr(exploit_script[:5000])}",
                    "timeout": 30,
                })
                self.tools_used.append("run_command")
                self.steps.append({
                    "step": "exploit_execution",
                    "result": run_result[:2000],
                })

                flag = self._extract_flag(run_result)

        return CTFSolution(
            challenge_id=challenge.id or "unknown",
            category=challenge.category,
            analysis=analysis,
            strategy="Pwn analysis + exploit generation",
            payload=self._extract_exploit_from_steps(),
            flag=flag,
            tools_used=list(set(self.tools_used)),
            steps=self.steps,
            confidence=0.8 if flag else 0.3,
        )

    def _extract_flag(self, text: str) -> Optional[str]:
        import re
        patterns = [r"flag\{[^}]+\}", r"FLAG\{[^}]+\}", r"ctf\{[^}]+\}"]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(0)
        return None

    def _extract_exploit_from_steps(self) -> Optional[str]:
        for step in reversed(self.steps):
            if step.get("step") == "exploit_execution":
                return step.get("result", "")[:1000]
        return None