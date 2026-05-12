"""
AdverLab - PGD (Projected Gradient Descent) 攻击实现
"""
import logging
from typing import Optional

import torch
import torch.nn as nn

logger = logging.getLogger(__name__)


class PGDAttack:
    """PGD 白盒攻击 - FGSM 的迭代增强版"""

    def __init__(
        self,
        model: nn.Module,
        epsilon: float = 0.03,
        alpha: float = 0.01,
        num_steps: int = 40,
        random_start: bool = True,
    ):
        self.model = model
        self.epsilon = epsilon
        self.alpha = alpha
        self.num_steps = num_steps
        self.random_start = random_start

    def attack(
        self,
        x: torch.Tensor,
        y: torch.Tensor,
        targeted: bool = False,
    ) -> torch.Tensor:
        """
        生成 PGD 对抗样本
        """
        x_orig = x.clone().detach()

        # 随机初始化
        if self.random_start:
            x_adv = x_orig + torch.empty_like(x_orig).uniform_(
                -self.epsilon, self.epsilon
            )
            x_adv = torch.clamp(x_adv, 0.0, 1.0)
        else:
            x_adv = x_orig.clone()

        loss_fn = nn.CrossEntropyLoss()

        for step in range(self.num_steps):
            x_adv.requires_grad_(True)

            output = self.model(x_adv)

            if targeted:
                loss = -loss_fn(output, y)
            else:
                loss = loss_fn(output, y)

            loss.backward()

            # PGD step: x' = x + alpha * sign(gradient)
            x_adv = x_adv.detach() + self.alpha * x_adv.grad.sign()

            # 投影到 epsilon 球内
            delta = torch.clamp(x_adv - x_orig, -self.epsilon, self.epsilon)
            x_adv = x_orig + delta

            # 裁剪到合法范围
            x_adv = torch.clamp(x_adv, 0.0, 1.0)

        return x_adv.detach()

    def evaluate(
        self,
        model: nn.Module,
        dataloader,
        device: str = "cpu",
    ) -> dict[str, float]:
        """评估 PGD 攻击效果"""
        model.eval()
        total = 0
        original_correct = 0
        adversarial_correct = 0
        total_l2 = 0.0

        for x, y in dataloader:
            x, y = x.to(device), y.to(device)
            total += x.size(0)

            # 原始准确率
            with torch.no_grad():
                orig_pred = model(x).argmax(dim=1)
                original_correct += (orig_pred == y).sum().item()

            # PGD 攻击
            x_adv = self.attack(x, y)

            # 对抗准确率
            with torch.no_grad():
                adv_pred = model(x_adv).argmax(dim=1)
                adversarial_correct += (adv_pred == y).sum().item()

            # L2 扰动量
            l2 = torch.norm((x_adv - x).view(x.size(0), -1), p=2, dim=1)
            total_l2 += l2.sum().item()

        original_acc = original_correct / total
        adversarial_acc = adversarial_correct / total
        avg_l2 = total_l2 / total

        return {
            "original_accuracy": original_acc,
            "adversarial_accuracy": adversarial_acc,
            "attack_success_rate": 1.0 - adversarial_acc,
            "perturbation_l_inf": self.epsilon,
            "avg_l2_norm": avg_l2,
            "num_steps": self.num_steps,
        }