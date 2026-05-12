"""
LLM-Guard - API 路由
"""
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException

from app.models.schemas import (
    AttackRequest,
    AttackType,
    LLMProvider,
    LLMTarget,
    SecurityReport,
)
from .evaluator import SecurityEvaluator
from .defense.filters import DefensePipeline

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/llm-guard", tags=["LLM-Guard"])

evaluator = SecurityEvaluator()
defense_pipeline = DefensePipeline()


@router.post("/attack", response_model=SecurityReport)
async def run_security_evaluation(request: AttackRequest):
    """对目标 LLM 执行安全评估"""
    logger.info(f"Running security evaluation on {request.target.name}")
    report = await evaluator.evaluate(request)
    return report


@router.post("/defend/check-input")
async def check_input_safety(text: str, provider: LLMProvider = LLMProvider.OPENAI):
    """检查输入是否安全"""
    result = await defense_pipeline.check_input(text)
    return result


@router.post("/defend/check-output")
async def check_output_safety(text: str):
    """检查输出是否安全"""
    result = await defense_pipeline.check_output(text)
    return result


@router.post("/defend/full-check")
async def full_safety_check(
    input_text: str,
    output_text: str,
    provider: LLMProvider = LLMProvider.OPENAI,
):
    """同时检查输入和输出"""
    result = await defense_pipeline.full_check(input_text, output_text)
    return result


@router.get("/attack-types")
async def list_attack_types():
    """列出支持的攻击类型"""
    return {
        "attack_types": [
            {"value": t.value, "label": t.value.replace("_", " ").title()}
            for t in AttackType
        ]
    }


@router.get("/categories")
async def list_categories():
    """列出安全测试类别"""
    from .attacks.prompt_injection import CATEGORY_GOALS
    return {
        "categories": [
            {"value": k, "description": v}
            for k, v in CATEGORY_GOALS.items()
        ]
    }