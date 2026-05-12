"""
CTF-AutoSolver - API 路由
"""
import json
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from app.models.schemas import (
    CTFCategory,
    CTFChallenge,
    CTFSolveRequest,
    CTFSolveResponse,
    LLMProvider,
)
from .solver import ctf_orchestrator
from .agent import CTFAgent

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ctf", tags=["CTF-AutoSolver"])


@router.post("/solve", response_model=CTFSolveResponse)
async def solve_challenge(request: CTFSolveRequest):
    """提交 CTF 题目并自动解题"""
    logger.info(f"Solving challenge: {request.challenge.title} ({request.challenge.category})")
    result = await ctf_orchestrator.solve(request)
    if result.status == "failed":
        raise HTTPException(status_code=500, detail=result.error)
    return result


@router.post("/analyze")
async def analyze_challenge(
    title: str,
    description: str,
    category: CTFCategory,
    url: Optional[str] = None,
    provider: LLMProvider = LLMProvider.OPENAI,
):
    """仅分析题目，不执行解题"""
    challenge = CTFChallenge(
        title=title,
        description=description,
        category=category,
        url=url,
    )
    result = await ctf_orchestrator.analyze_only(challenge, provider.value)
    return result


@router.post("/solve/stream")
async def solve_challenge_stream(request: CTFSolveRequest):
    """流式解题，逐步返回 Agent 思考过程"""
    challenge = request.challenge
    provider = request.provider.value

    async def event_generator():
        agent = CTFAgent(provider=provider)
        async for event in agent.solve_stream(challenge):
            yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
    )


@router.get("/tasks/{task_id}")
async def get_task_status(task_id: str):
    """获取解题任务状态"""
    task = ctf_orchestrator.get_task_status(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


@router.get("/categories")
async def list_categories():
    """列出支持的题目类别"""
    return {
        "categories": [
            {"value": c.value, "label": c.value.upper()} for c in CTFCategory
        ]
    }