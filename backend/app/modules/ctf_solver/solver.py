"""
CTF-AutoSolver - 统一调度器
根据题目类别自动路由到对应的专用解题器
"""
import logging
import uuid
from datetime import datetime
from typing import Optional

from app.core.llm import llm_router
from app.models.schemas import (
    CTFCategory,
    CTFChallenge,
    CTFSolveRequest,
    CTFSolveResponse,
    CTFSolution,
    LLMProvider,
    TaskStatus,
)

from .agent import CTFAgent
from .crypto_solver import CryptoSolver
from .pwn_solver import PwnSolver
from .reverse_solver import ReverseSolver
from .web_solver import WebSolver

logger = logging.getLogger(__name__)

# 题型到解题器的映射
CATEGORY_SOLVER_MAP = {
    CTFCategory.WEB: WebSolver,
    CTFCategory.PWN: PwnSolver,
    CTFCategory.REVERSE: ReverseSolver,
    CTFCategory.CRYPTO: CryptoSolver,
    # MISC 和 FORENSICS 使用通用 Agent
    CTFCategory.MISC: None,
    CTFCategory.FORENSICS: None,
}


class CTFSolverOrchestrator:
    """CTF 解题调度器"""

    def __init__(self):
        self._tasks: dict[str, dict] = {}

    async def solve(self, request: CTFSolveRequest) -> CTFSolveResponse:
        """
        解题入口 - 根据题型自动路由
        """
        task_id = str(uuid.uuid4())
        challenge = request.challenge
        provider = request.provider.value if isinstance(request.provider, LLMProvider) else request.provider

        self._tasks[task_id] = {
            "status": TaskStatus.RUNNING,
            "challenge": challenge,
            "started_at": datetime.now(),
        }

        try:
            solution = await self._dispatch_solve(challenge, provider)
            self._tasks[task_id]["status"] = TaskStatus.COMPLETED
            return CTFSolveResponse(
                task_id=task_id,
                status=TaskStatus.COMPLETED,
                solution=solution,
            )
        except Exception as e:
            logger.error(f"CTF solve error [{task_id}]: {e}", exc_info=True)
            self._tasks[task_id]["status"] = TaskStatus.FAILED
            return CTFSolveResponse(
                task_id=task_id,
                status=TaskStatus.FAILED,
                error=str(e),
            )

    async def _dispatch_solve(self, challenge: CTFChallenge, provider: str) -> CTFSolution:
        """根据题型分配解题器"""
        category = challenge.category
        solver_class = CATEGORY_SOLVER_MAP.get(category)

        if solver_class is not None:
            # 使用专用解题器
            solver = solver_class(provider=provider)
            logger.info(f"[CTF Solver] Using {solver_class.__name__} for {category.value}")
            return await solver.solve(challenge)
        else:
            # 使用通用 ReAct Agent
            logger.info(f"[CTF Solver] Using CTFAgent for {category.value}")
            agent = CTFAgent(provider=provider)
            return await agent.solve(challenge)

    async def analyze_only(self, challenge: CTFChallenge, provider: str = "openai") -> dict:
        """
        仅分析，不解题
        返回 LLM 对题目的分析和解题思路
        """
        analysis = await llm_router.chat(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a CTF challenge analyst. Analyze the given challenge and provide:\n"
                        "1. Challenge type identification\n"
                        "2. Likely vulnerability/technique\n"
                        "3. Recommended solving approach\n"
                        "4. Estimated difficulty (1-5)\n"
                        "5. Required tools/knowledge"
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        f"Title: {challenge.title}\n"
                        f"Category: {challenge.category.value}\n"
                        f"Description: {challenge.description}\n"
                        f"URL: {challenge.url or 'N/A'}\n"
                        f"Attachments: {', '.join(challenge.attachment_paths) if challenge.attachment_paths else 'None'}"
                    ),
                },
            ],
            provider=provider,
            temperature=0.3,
        )
        return {
            "challenge_id": challenge.id,
            "category": challenge.category.value,
            "analysis": analysis,
        }

    def get_task_status(self, task_id: str) -> Optional[dict]:
        """获取任务状态"""
        return self._tasks.get(task_id)


# 全局单例
ctf_orchestrator = CTFSolverOrchestrator()