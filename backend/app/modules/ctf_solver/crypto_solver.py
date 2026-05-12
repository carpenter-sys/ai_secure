"""
CTF-AutoSolver - Crypto 题型专用解题器
针对密码学题目的专项解题逻辑
"""
import logging
from typing import Any, Optional

from app.core.llm import llm_router
from app.core.tools import tool_registry
from app.models.schemas import CTFChallenge, CTFSolution

logger = logging.getLogger(__name__)

CRYPTO_SYSTEM_PROMPT = """You are a Cryptography CTF expert. Solve cryptographic challenges using mathematical analysis and known attacks.

Common Crypto CTF attack vectors:
- **Classical Ciphers**: Caesar, Vigenere, Substitution, Transposition
- **RSA Attacks**: Small exponent, Wiener's attack, Hastad's broadcast, common modulus, factorization
- **Block Cipher**: ECB mode detection, CBC bit-flipping, padding oracle
- **Stream Cipher**: Reuse of key/nonce, bit-flipping
- **Hash**: Collision, length extension, MD5/SHA1 weaknesses
- **Elliptic Curve**: Invalid curve, Pohlig-Hellman
- **Lattice**: LLL reduction, CVP/SVP
- **Custom Ciphers**: Identify and break custom encryption schemes

For each challenge:
1. Identify the cipher/algorithm type from the description
2. Determine which attack is applicable
3. Implement the attack using available tools (z3_solve, run_command with Python)
4. Extract the flag
"""


class CryptoSolver:
    """密码学 CTF 解题器"""

    def __init__(self, provider: str = "openai"):
        self.provider = provider
        self.tools_used: list[str] = []
        self.steps: list[dict[str, Any]] = []

    async def solve(self, challenge: CTFChallenge) -> CTFSolution:
        """自动解题"""
        # LLM 初始分析
        analysis = await llm_router.chat(
            messages=[
                {"role": "system", "content": CRYPTO_SYSTEM_PROMPT},
                {"role": "user", "content": (
                    f"Challenge: {challenge.title}\n"
                    f"Description: {challenge.description}\n\n"
                    f"Analyze this crypto challenge:\n"
                    f"1. What cipher/algorithm is being used?\n"
                    f"2. What specific attack is applicable?\n"
                    f"3. What information is needed to execute the attack?\n"
                    f"4. Provide a Python script or z3_solve call to break it."
                )},
            ],
            provider=self.provider,
            temperature=0.3,
        )

        self.steps.append({
            "step": "initial_analysis",
            "content": analysis[:1000],
        })

        # 尝试用 LLM + 工具解题
        flag = None
        result = await llm_router.chat_with_tools(
            messages=[
                {"role": "system", "content": CRYPTO_SYSTEM_PROMPT},
                {"role": "user", "content": (
                    f"Challenge: {challenge.title}\n"
                    f"Description: {challenge.description}\n\n"
                    f"Your analysis: {analysis}\n\n"
                    f"Now solve this challenge. Use z3_solve for constraint problems, "
                    f"or run_command to execute Python scripts. Extract the flag."
                )},
            ],
            tools=tool_registry.get_openai_tools_schema(),
            provider=self.provider,
            temperature=0.3,
        )

        tool_calls = result.get("tool_calls", [])
        reasoning = result.get("content", "")

        self.steps.append({
            "step": "solving_attempt",
            "reasoning": reasoning[:500],
        })

        for tc in tool_calls:
            tool_name = tc["name"]
            tool_args = eval(tc["arguments"]) if isinstance(tc["arguments"], str) else tc["arguments"]
            self.tools_used.append(tool_name)

            observation = await tool_registry.execute_tool(tool_name, tool_args)
            self.steps.append({
                "step": "tool_execution",
                "tool": tool_name,
                "arguments": str(tool_args)[:200],
                "observation": observation[:2000],
            })

            flag = self._extract_flag(observation)
            if flag:
                break

        if not flag and reasoning:
            flag = self._extract_flag(reasoning)

        return CTFSolution(
            challenge_id=challenge.id or "unknown",
            category=challenge.category,
            analysis=analysis,
            strategy="Crypto analysis + tool-assisted solving",
            payload=self._extract_script_from_steps(),
            flag=flag,
            tools_used=list(set(self.tools_used)),
            steps=self.steps,
            confidence=0.85 if flag else 0.3,
        )

    def _extract_flag(self, text: str) -> Optional[str]:
        import re
        patterns = [r"flag\{[^}]+\}", r"FLAG\{[^}]+\}", r"ctf\{[^}]+\}"]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(0)
        return None

    def _extract_script_from_steps(self) -> Optional[str]:
        for step in self.steps:
            if step.get("tool") == "run_command":
                return step.get("arguments", "")[:500]
        return None