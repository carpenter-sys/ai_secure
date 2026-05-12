"""
AdverLab - 实验管理器
统一管理攻防实验，记录实验配置和结果
"""
import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import torch
import torch.nn as nn
from torch.utils.data import DataLoader

from app.models.schemas import (
    AdversarialAttackType,
    DefenseType,
    ExperimentConfig,
    ExperimentResult,
)
from .attacks.fgsm import FGSMAttack
from .attacks.pgd import PGDAttack
from .attacks.cw import CWAttack
from .defenses.adversarial_training import AdversarialTraining, InputPreprocessing

logger = logging.getLogger(__name__)


class ExperimentManager:
    """攻防实验管理器"""

    def __init__(self, results_dir: str = "results/adver_lab"):
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.experiments: dict[str, dict] = {}

    def run_attack_experiment(
        self,
        config: ExperimentConfig,
        model: nn.Module,
        dataloader: DataLoader,
        device: str = "cpu",
    ) -> ExperimentResult:
        """运行攻击实验"""
        experiment_id = str(uuid.uuid4())[:8]
        logger.info(f"[Experiment {experiment_id}] Running {config.attack_type.value} attack")

        # 创建攻击器
        attacker = self._create_attacker(model, config)

        # 执行攻击评估
        attack_results = attacker.evaluate(model, dataloader, device)

        # 如果指定了防御，运行防御实验
        robust_accuracy = None
        if config.defense_type:
            defense_results = self._run_defense(
                config.defense_type,
                model,
                dataloader,
                attacker,
                device,
                config.defense_params,
            )
            robust_accuracy = defense_results.get("adversarial_accuracy_with_defense")

        # 组装结果
        result = ExperimentResult(
            experiment_name=config.name,
            original_accuracy=attack_results["original_accuracy"],
            adversarial_accuracy=attack_results["adversarial_accuracy"],
            robust_accuracy=robust_accuracy,
            attack_success_rate=attack_results["attack_success_rate"],
            perturbation_norm=attack_results.get("perturbation_l_inf", 0.0),
            config=config,
            timestamp=datetime.now(),
        )

        # 记录实验
        self.experiments[experiment_id] = {
            "config": config.model_dump(),
            "results": result.model_dump(),
        }

        # 保存结果
        self._save_result(experiment_id, result)

        return result

    def run_defense_experiment(
        self,
        model: nn.Module,
        train_loader: DataLoader,
        val_loader: DataLoader,
        config: ExperimentConfig,
        device: str = "cpu",
    ) -> dict[str, Any]:
        """运行防御训练实验"""
        logger.info(f"Running defense training: {config.defense_type}")

        if config.defense_type == DefenseType.ADVERSARIAL_TRAINING:
            defense = AdversarialTraining(
                model=model,
                epsilon=config.epsilon,
                **config.defense_params,
            )
            train_history = defense.train(
                train_loader=train_loader,
                val_loader=val_loader,
                device=device,
            )

            # 训练后评估鲁棒性
            attacker = self._create_attacker(model, config)
            attack_results = attacker.evaluate(model, val_loader, device)

            return {
                "defense_type": "adversarial_training",
                "training_history": train_history,
                "post_training_evaluation": attack_results,
            }

        elif config.defense_type == DefenseType.INPUT_PREPROCESSING:
            preprocessing = InputPreprocessing(
                method=config.defense_params.get("method", "bit_depth_reduction"),
            )
            attacker = self._create_attacker(model, config)
            defense_results = preprocessing.evaluate_defense(
                model, val_loader,
                lambda x, y: attacker.attack(x, y),
                device,
            )
            return defense_results

        return {"error": f"Unknown defense type: {config.defense_type}"}

    def _create_attacker(self, model: nn.Module, config: ExperimentConfig):
        """根据配置创建攻击器"""
        if config.attack_type == AdversarialAttackType.FGSM:
            return FGSMAttack(model, epsilon=config.epsilon)
        elif config.attack_type == AdversarialAttackType.PGD:
            return PGDAttack(
                model,
                epsilon=config.epsilon,
                alpha=config.attack_params.get("alpha", config.epsilon / 4),
                num_steps=config.attack_params.get("num_steps", 40),
            )
        elif config.attack_type == AdversarialAttackType.CW:
            return CWAttack(
                model,
                c=config.attack_params.get("c", 1.0),
                num_steps=config.attack_params.get("num_steps", 100),
            )
        else:
            raise ValueError(f"Unsupported attack type: {config.attack_type}")

    def _run_defense(
        self,
        defense_type: DefenseType,
        model: nn.Module,
        dataloader: DataLoader,
        attacker,
        device: str,
        defense_params: dict,
    ) -> dict[str, float]:
        """运行单一防御评估"""
        if defense_type == DefenseType.INPUT_PREPROCESSING:
            preprocessing = InputPreprocessing(
                method=defense_params.get("method", "bit_depth_reduction"),
            )
            return preprocessing.evaluate_defense(
                model, dataloader,
                lambda x, y: attacker.attack(x, y),
                device,
            )
        return {}

    def _save_result(self, experiment_id: str, result: ExperimentResult):
        """保存实验结果到文件"""
        result_path = self.results_dir / f"{experiment_id}.json"
        with open(result_path, "w") as f:
            json.dump(result.model_dump(), f, indent=2, default=str)
        logger.info(f"Experiment result saved to {result_path}")

    def list_experiments(self) -> list[dict]:
        """列出所有实验"""
        return [
            {"id": eid, **exp.get("config", {})}
            for eid, exp in self.experiments.items()
        ]

    def get_experiment(self, experiment_id: str) -> Optional[dict]:
        """获取实验详情"""
        return self.experiments.get(experiment_id)


# 全局单例
experiment_manager = ExperimentManager()