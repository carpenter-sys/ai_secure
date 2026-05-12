"""
CTF-AutoSolver - Reverse 题型专用解题器
针对逆向工程题目的专项解题逻辑
"""
import logging
from typing import Any, Optional

from app.core.llm import llm_router
from app.core.tools import tool_registry
from app.models.schemas import CTFChallenge, CTFSolution

logger = logging.getLogger(__name__)

REVERSE_SYSTEM_PROMPT = """You are a Reverse Engineering CTF expert. Analyze binary files and recover hidden logic.

Common Reverse CTF techniques:
- **Static Analysis**: Disassembly, string analysis, symbol recovery
- **Dynamic Analysis**: Debugging, tracing, breakpoint setting
- **Deobfuscation**: Control flow flattening, string encryption, anti-debugging bypass
- **Algorithm Recovery**: Custom encryption, hashing, encoding schemes
- **Packing/Unpacking**: UPX, custom packers, VM-based protection

For each challenge:
1. Identify the file type and architecture
2. Extract strings and symbols
3. Identify key functions and logic
4. Recover the algorithm
5. Reverse the algorithm to find the flag
"""


class ReverseSolver:
    """逆向工程 CTF 解题器"""

    def __init__(self, provider: str = "openai"):
        self.provider = provider
        self.tools_used: list[str] = []
        self.steps: list[dict[str, Any]] = []

    async def analyze_binary(self, challenge: CTFChallenge) -> dict[str, Any]:
        """分析二进制文件"""
        analysis_parts = []

        # 使用 file 命令识别文件类型
        if challenge.attachment_paths:
            for path in challenge.attachment_paths:
                file_result = await tool_registry.execute_tool("run_command", {
                    "command": f"file {path}",
                })
                self.tools_used.append("run_command")
                analysis_parts.append(f"File type: {file_result}")

                # 提取字符串
                strings_result = await tool_registry.execute_tool("run_command", {
                    "command": f"strings {path} | head -100",
                })
                self.tools_used.append("run_command")
                analysis_parts.append(f"Strings: {strings_result}")

                # 检查是否加壳
                checksec_result = await tool_registry.execute_tool("run_command", {
                    "command": f"checksec --file={path} 2>/dev/null || echo 'checksec not available'",
                })
                self.tools_used.append("run_command")
                analysis_parts.append(f"Security: {checksec_result}")

        # LLM 分析
        combined_analysis = "\n\n".join(analysis_parts)
        llm_analysis = await llm_router.chat(
            messages=[
                {"role": "system", "content": REVERSE_SYSTEM_PROMPT},
                {"role": "user", "content": (
                    f"Challenge: {challenge.title}\n"
                    f"Description: {challenge.description}\n\n"
                    f"Binary analysis results:\n{combined_analysis}\n\n"
                    f"Analyze this binary. Identify:\n"
                    f"1. File type and architecture\n"
                    f"2. Key functions and entry points\n"
                    f"3. Possible algorithm/logic used\n"
                    f"4. Recommended approach to extract the flag"
                )},
            ],
            provider=self.provider,
            temperature=0.3,
        )

        return {
            "static_analysis": combined_analysis,
            "llm_analysis": llm_analysis,
        }

    async def solve(self, challenge: CTFChallenge) -> CTFSolution:
        """自动解题"""
        if not challenge.attachment_paths:
            # 没有附件，只用描述分析
            analysis = await llm_router.chat(
                messages=[
                    {"role": "system", "content": REVERSE_SYSTEM_PROMPT},
                    {"role": "user", "content": (
                        f"Challenge: {challenge.title}\n"
                        f"Description: {challenge.description}\n"
                        f"No binary file provided. Analyze the description and provide a solution approach."
                    )},
                ],
                provider=self.provider,
                temperature=0.3,
            )
            return CTFSolution(
                challenge_id=challenge.id or "unknown",
                category=challenge.category,
                analysis=analysis,
                strategy="Description-based analysis",
                flag=None,
                tools_used=[],
                steps=self.steps,
                confidence=0.2,
            )

        analysis = await self.analyze_binary(challenge)

        # 尝试用 Ghidra/r2 反编译 + LLM 分析
        for path in challenge.attachment_paths:
            # 尝试 radare2 分析
            r2_result = await tool_registry.execute_tool("run_command", {
                "command": f"r2 -q -c 'aaa; afl; pdf@main' {path} 2>/dev/null | head -200",
                "timeout": 60,
            })
            self.tools_used.append("run_command")
            self.steps.append({
                "step": "r2_analysis",
                "file": path,
                "result": r2_result[:2000],
            })

            # LLM 分析反编译结果
            decompile_analysis = await llm_router.chat(
                messages=[
                    {"role": "system", "content": REVERSE_SYSTEM_PROMPT},
                    {"role": "user", "content": (
                        f"Disassembly/decompilation of {path}:\n{r2_result[:4000]}\n\n"
                        f"Previous analysis: {analysis.get('llm_analysis', '')}\n\n"
                        f"Based on this, identify the flag-checking logic and provide the flag."
                    )},
                ],
                provider=self.provider,
                temperature=0.3,
            )

            self.steps.append({
                "step": "llm_decompile_analysis",
                "content": decompile_analysis[:500],
            })

            # 检查 flag
            flag = self._extract_flag(decompile_analysis)
            if flag:
                return CTFSolution(
                    challenge_id=challenge.id or "unknown",
                    category=challenge.category,
                    analysis=decompile_analysis,
                    strategy="Radare2 + LLM analysis",
                    flag=flag,
                    tools_used=list(set(self.tools_used)),
                    steps=self.steps,
                    confidence=0.85,
                )

        return CTFSolution(
            challenge_id=challenge.id or "unknown",
            category=challenge.category,
            analysis=analysis.get("llm_analysis", ""),
            strategy="Static analysis + LLM reasoning",
            flag=None,
            tools_used=list(set(self.tools_used)),
            steps=self.steps,
            confidence=0.3,
        )

    def _extract_flag(self, text: str) -> Optional[str]:
        import re
        patterns = [r"flag\{[^}]+\}", r"FLAG\{[^}]+\}", r"ctf\{[^}]+\}"]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(0)
        return None