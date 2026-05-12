"""
AdverLab - C&W (Carlini & Wagner) 攻击实现
"""
import logging
from typing import Optional

import torch
import torch.nn as nn

logger = logging.getLogger(__name__)


class CWAttack:
    """C&W L2 攻击 - 基于优化的强攻击"""

    def __init__(
        self,
        model: nn.Module,
        c: float = 1.0,
        kappa: float = 0.0,
        num_steps: int = 100,
        lr: float = 0.01,
    ):
        self.model = model
        self.c = c  # 置信度与扰动量的权衡参数
        self.kappa = kappa  # 置信度参数
        self.num_steps = num_steps
        self.lr = lr

    def attack(
        self,
        x: torch.Tensor,
        y: torch.Tensor,
        targeted: bool = False,
        num_classes: int = 10,
    ) -> torch.Tensor:
        """
        C&W 攻击：通过 tanh 变换实现无约束优化
        """
        device = x.device
        x_orig = x.clone().detach()

        # 使用 tanh 变换确保输出在 [0, 1] 范围内
        # x = 0.5 * (tanh(w) + 1)
        w = torch.atanh(2 * x_orig - 1).detach().requires_grad_(True)
        optimizer = torch.optim.Adam([w], lr=self.lr)

        for step in range(self.num_steps):
            # 从 w 恢复 x
            x_adv = 0.5 * (torch.tanh(w) + 1)

            # 计算模型输出
            output = self.model(x_adv)

            # 计算损失
            loss = self._cw_loss(output, y, x_adv, x_orig, targeted, num_classes)

            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

        x_adv = 0.5 * (torch.tanh(w) + 1)
        return x_adv.detach()

    def _cw_loss(
        self,
        output: torch.Tensor,
        y: torch.Tensor,
        x_adv: torch.Tensor,
        x_orig: torch.Tensor,
        targeted: bool,
        num_classes: int,
    ) -> torch.Tensor:
        """C&W 损失函数"""
        # L2 扰动量
        l2_dist = torch.sum((x_adv - x_orig) ** 2)

        # 分类损失
        one_hot = torch.zeros_like(output).scatter_(1, y.unsqueeze(1), 1)
        wrong_logit = output.clone()
        wrong_logit[one_hot.bool()] = -float("inf")
        wrong_logit = wrong_logit.max(dim=1)[0]
        target_logit = output[torch.arange(output.size(0)), y]

        if targeted:
            # 定向攻击：最小化 target_logit - wrong_logit
            class_loss = torch.clamp(wrong_logit - target_logit + self.kappa, min=0)
        else:
            # 非定向：最大化 target_logit - wrong_logit
            class_loss = torch.clamp(target_logit - wrong_logit + self.kappa, min=0)

        # 总损失 = c * class_loss + l2_dist
        total_loss = self.c * class_loss.sum() + l2_dist

        return total_loss

    def evaluate(
        self,
        model: nn.Module,
        dataloader,
        device: str = "cpu",
        num_classes: int = 10,
    ) -> dict[str, float]:
        """评估 C&W 攻击效果"""
        model.eval()
        total = 0
        original_correct = 0
        adversarial_correct = 0
        total_l2 = 0.0

        for x, y in dataloader:
            x, y = x.to(device), y.to(device)
            total += x.size(0)

            with torch.no_grad():
                orig_pred = model(x).argmax(dim=1)
                original_correct += (orig_pred == y).sum().item()

            x_adv = self.attack(x, y, num_classes=num_classes)

            with torch.no_grad():
                adv_pred = model(x_adv).argmax(dim=1)
                adversarial_correct += (adv_pred == y).sum().item()

            l2 = torch.norm((x_adv - x).view(x.size(0), -1), p=2, dim=1)
            total_l2 += l2.sum().item()

        return {
            "original_accuracy": original_correct / total,
            "adversarial_accuracy": adversarial_correct / total,
            "attack_success_rate": 1.0 - adversarial_correct / total,
            "avg_l2_norm": total_l2 / total,
            "c_parameter": self.c,
            "kappa": self.kappa,
        }