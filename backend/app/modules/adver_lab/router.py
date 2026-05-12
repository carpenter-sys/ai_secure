"""
AdverLab - API 路由
"""
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException

from app.models.schemas import (
    AdversarialAttackType,
    DefenseType,
    ExperimentConfig,
    ExperimentResult,
)
from .experiment import experiment_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/adver-lab", tags=["AdverLab"])


@router.post("/experiment/run")
async def run_experiment(config: ExperimentConfig):
    """
    运行攻防实验
    注意：需要先加载模型和数据，此处为配置入口
    """
    try:
        # 实际运行需要模型和 DataLoader，这里返回配置确认
        experiment_id = str(id(config))
        experiment_manager.experiments[experiment_id] = {
            "config": config.model_dump(),
            "status": "configured",
        }
        return {
            "experiment_id": experiment_id,
            "config": config.model_dump(),
            "status": "configured - ready to run with model and data",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/experiment/list")
async def list_experiments():
    """列出所有实验"""
    return {"experiments": experiment_manager.list_experiments()}


@router.get("/experiment/{experiment_id}")
async def get_experiment(experiment_id: str):
    """获取实验详情"""
    exp = experiment_manager.get_experiment(experiment_id)
    if not exp:
        raise HTTPException(status_code=404, detail="Experiment not found")
    return exp


@router.get("/attack-types")
async def list_attack_types():
    """列出支持的攻击类型"""
    return {
        "attack_types": [
            {"value": t.value, "label": t.value.upper(), "category": "white_box"}
            for t in AdversarialAttackType
        ]
    }


@router.get("/defense-types")
async def list_defense_types():
    """列出支持的防御类型"""
    return {
        "defense_types": [
            {"value": t.value, "label": t.value.replace("_", " ").title()}
            for t in DefenseType
        ]
    }


@router.post("/quick-test")
async def quick_adversarial_test(
    attack_type: AdversarialAttackType = AdversarialAttackType.FGSM,
    epsilon: float = 0.03,
    dataset: str = "mnist",
):
    """
    快速对抗测试 - 使用预设模型和数据集
    返回测试配置和预期结果
    """
    config = ExperimentConfig(
        name=f"quick_test_{attack_type.value}",
        attack_type=attack_type,
        epsilon=epsilon,
        dataset=dataset,
    )
    return {
        "config": config.model_dump(),
        "instructions": (
            f"To run this test:\n"
            f"1. Load {dataset} dataset\n"
            f"2. Train or load a model\n"
            f"3. Run experiment with the above config\n"
            f"4. Expected attack success rate for {attack_type.value} "
            f"with epsilon={epsilon} on {dataset}: ~70-90%"
        ),
    }