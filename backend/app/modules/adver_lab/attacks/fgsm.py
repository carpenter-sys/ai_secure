"""
AdverLab - FGSM (Fast Gradient Sign Method) 攻击实现
"""
import logging
from typing import Optional

import numpy as np
import torch
import torch.nn as nn

logger = logging.getLogger(__name__)


class FGSMAttack:
    """FGSM 白盒攻击"""

    def __init__(self, model: nn.Module, epsilon: float = 0.03):
        self.model = model
        self.epsilon = epsilon

    def attack(
        self,
        x: torch.Tensor,
        y: torch.Tensor,
        targeted: bool = False,
    ) -> torch.Tensor:
        """
        生成对抗样本
        Args:
            x: 原始输入 (需要 requires_grad=True)
            y: 真实标签（untargeted）或目标标签（targeted）
            targeted: 是否为定向攻击
        """
        x_adv = x.clone().detach().requires_grad_(True)

        output = self.model(x_adv)
        loss_fn = nn.CrossEntropyLoss()

        if targeted:
            loss = -loss_fn(output, y)  # 定向攻击：最大化目标类概率
        else:
            loss = loss_fn(output, y)  # 非定向：最大化损失

        loss.backward()

        # FGSM: x' = x + epsilon * sign(gradient)
        perturbation = self.epsilon * x_adv.grad.sign()
        x_adv = x_adv + perturbation

        # 裁剪到合法范围
        x_adv = torch.clamp(x_adv, 0.0, 1.0)

        return x_adv.detach()

    def attack_batch(
        self,
        dataloader,
        device: str = "cpu",
        targeted: bool = False,
        target_class: Optional[int] = None,
    ) -> tuple[list[torch.Tensor], list[torch.Tensor], list[torch.Tensor]]:
        """
        对整个数据集执行 FGSM 攻击
        Returns: (original_samples, adversarial_samples, labels)
        """
        self.model.eval()
        originals = []
        adversarials = []
        labels = []

        for x, y in dataloader:
            x, y = x.to(device), y.to(device)

            if targeted and target_class is not None:
                target_labels = torch.full_like(y, target_class)
                x_adv = self.attack(x, target_labels, targeted=True)
            else:
                x_adv = self.attack(x, y, targeted=False)

            originals.append(x.cpu())
            adversarials.append(x_adv.cpu())
            labels.append(y.cpu())

        return originals, adversarials, labels

    def evaluate(
        self,
        model: nn.Module,
        dataloader,
        device: str = "cpu",
    ) -> dict[str, float]:
        """评估攻击效果"""
        model.eval()
        total = 0
        original_correct = 0
        adversarial_correct = 0

        for x, y in dataloader:
            x, y = x.to(device), y.to(device)
            total += x.size(0)

            # 原始样本准确率
            with torch.no_grad():
                orig_pred = model(x).argmax(dim=1)
                original_correct += (orig_pred == y).sum().item()

            # 对抗样本准确率
            x_adv = self.attack(x, y)
            with torch.no_grad():
                adv_pred = model(x_adv).argmax(dim=1)
                adversarial_correct += (adv_pred == y).sum().item()

        original_acc = original_correct / total
        adversarial_acc = adversarial_correct / total
        attack_success_rate = 1.0 - adversarial_acc

        # 计算扰动范数
        perturbation = self.epsilon  # FGSM 扰动量等于 epsilon

        return {
            "original_accuracy": original_acc,
            "adversarial_accuracy": adversarial_acc,
            "attack_success_rate": attack_success_rate,
            "perturbation_l_inf": perturbation,
        }