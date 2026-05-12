"""
AdverLab - 对抗训练防御实现
"""
import logging
from typing import Optional

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset

logger = logging.getLogger(__name__)


class AdversarialTraining:
    """对抗训练防御"""

    def __init__(
        self,
        model: nn.Module,
        epsilon: float = 0.03,
        alpha: float = 0.01,
        pgd_steps: int = 7,
        mix_ratio: float = 0.5,
    ):
        """
        Args:
            model: 要增强鲁棒性的模型
            epsilon: 对抗扰动上界
            alpha: PGD 步长
            pgd_steps: 内部 PGD 迭代步数
            mix_ratio: 对抗样本与正常样本的混合比例
        """
        self.model = model
        self.epsilon = epsilon
        self.alpha = alpha
        self.pgd_steps = pgd_steps
        self.mix_ratio = mix_ratio

    def _pgd_attack_inner(self, x: torch.Tensor, y: torch.Tensor) -> torch.Tensor:
        """内部 PGD 攻击，用于生成对抗训练样本"""
        x_orig = x.clone().detach()
        x_adv = x_orig + torch.zeros_like(x_orig).uniform_(-self.epsilon, self.epsilon)
        x_adv = torch.clamp(x_adv, 0.0, 1.0)

        loss_fn = nn.CrossEntropyLoss()

        for _ in range(self.pgd_steps):
            x_adv.requires_grad_(True)
            output = self.model(x_adv)
            loss = loss_fn(output, y)
            loss.backward()

            x_adv = x_adv.detach() + self.alpha * x_adv.grad.sign()
            delta = torch.clamp(x_adv - x_orig, -self.epsilon, self.epsilon)
            x_adv = x_orig + delta
            x_adv = torch.clamp(x_adv, 0.0, 1.0)

        return x_adv.detach()

    def train(
        self,
        train_loader: DataLoader,
        val_loader: Optional[DataLoader] = None,
        epochs: int = 10,
        learning_rate: float = 1e-3,
        device: str = "cpu",
    ) -> dict[str, list[float]]:
        """
        执行对抗训练
        """
        self.model.to(device)
        optimizer = optim.Adam(self.model.parameters(), lr=learning_rate)
        scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)
        loss_fn = nn.CrossEntropyLoss()

        train_losses = []
        val_losses = []
        val_accuracies = []

        for epoch in range(epochs):
            self.model.train()
            epoch_loss = 0.0
            n_batches = 0

            for x, y in train_loader:
                x, y = x.to(device), y.to(device)
                batch_size = x.size(0)

                # 生成对抗样本
                n_adv = int(batch_size * self.mix_ratio)
                if n_adv > 0:
                    x_adv = self._pgd_attack_inner(x[:n_adv], y[:n_adv])
                    x_mixed = torch.cat([x_adv, x[n_adv:]], dim=0)
                else:
                    x_mixed = x

                # 前向传播
                optimizer.zero_grad()
                output = self.model(x_mixed)
                loss = loss_fn(output, y)
                loss.backward()
                optimizer.step()

                epoch_loss += loss.item()
                n_batches += 1

            scheduler.step()
            avg_loss = epoch_loss / max(n_batches, 1)
            train_losses.append(avg_loss)

            # 验证
            if val_loader is not None:
                val_loss, val_acc = self._evaluate(val_loader, loss_fn, device)
                val_losses.append(val_loss)
                val_accuracies.append(val_acc)

                if (epoch + 1) % 5 == 0:
                    logger.info(
                        f"Epoch {epoch+1}/{epochs} - "
                        f"Train Loss: {avg_loss:.4f}, "
                        f"Val Loss: {val_loss:.4f}, "
                        f"Val Acc: {val_acc:.4f}"
                    )

        return {
            "train_losses": train_losses,
            "val_losses": val_losses,
            "val_accuracies": val_accuracies,
        }

    def _evaluate(
        self, loader: DataLoader, loss_fn: nn.Module, device: str
    ) -> tuple[float, float]:
        """评估模型"""
        self.model.eval()
        total_loss = 0.0
        total_correct = 0
        total = 0

        with torch.no_grad():
            for x, y in loader:
                x, y = x.to(device), y.to(device)
                output = self.model(x)
                loss = loss_fn(output, y)
                total_loss += loss.item()
                total_correct += (output.argmax(dim=1) == y).sum().item()
                total += x.size(0)

        return total_loss / len(loader), total_correct / max(total, 1)


class InputPreprocessing:
    """输入预处理防御"""

    def __init__(self, method: str = "bit_depth_reduction", bit_depth: int = 4):
        self.method = method
        self.bit_depth = bit_depth

    def defend(self, x: torch.Tensor) -> torch.Tensor:
        """对输入进行预处理以去除对抗扰动"""
        if self.method == "bit_depth_reduction":
            return self._bit_depth_reduction(x)
        elif self.method == "jpeg_compression":
            return self._jpeg_compression_sim(x)
        elif self.method == "gaussian_noise":
            return self._gaussian_noise(x)
        elif self.method == "median_filter":
            return self._median_filter(x)
        else:
            return x

    def _bit_depth_reduction(self, x: torch.Tensor) -> torch.Tensor:
        """位深度缩减"""
        levels = 2 ** self.bit_depth
        x_reduced = torch.round(x * levels) / levels
        return torch.clamp(x_reduced, 0.0, 1.0)

    def _jpeg_compression_sim(self, x: torch.Tensor) -> torch.Tensor:
        """模拟 JPEG 压缩效果"""
        # 简化实现：使用量化和反量化
        quality = 0.5
        x_quantized = torch.round(x / quality) * quality
        return torch.clamp(x_quantized, 0.0, 1.0)

    def _gaussian_noise(self, x: torch.Tensor, sigma: float = 0.05) -> torch.Tensor:
        """高斯噪声去噪"""
        noise = torch.randn_like(x) * sigma
        x_noisy = x + noise
        return torch.clamp(x_noisy, 0.0, 1.0)

    def _median_filter(self, x: torch.Tensor) -> torch.Tensor:
        """中值滤波"""
        # 简化实现：使用平均池化近似
        import torch.nn.functional as F
        if x.dim() == 4:  # (B, C, H, W)
            x_filtered = F.avg_pool2d(x, kernel_size=3, stride=1, padding=1)
        else:
            x_filtered = x
        return torch.clamp(x_filtered, 0.0, 1.0)

    def evaluate_defense(
        self,
        model: nn.Module,
        dataloader,
        attack_fn,
        device: str = "cpu",
    ) -> dict[str, float]:
        """评估预处理防御效果"""
        model.eval()
        total = 0
        orig_correct = 0
        adv_correct_no_defense = 0
        adv_correct_with_defense = 0

        for x, y in dataloader:
            x, y = x.to(device), y.to(device)
            total += x.size(0)

            # 原始准确率
            with torch.no_grad():
                orig_pred = model(x).argmax(dim=1)
                orig_correct += (orig_pred == y).sum().item()

            # 无防御对抗样本
            x_adv = attack_fn(x, y)
            with torch.no_grad():
                adv_pred = model(x_adv).argmax(dim=1)
                adv_correct_no_defense += (adv_pred == y).sum().item()

            # 有防御对抗样本
            x_adv_defended = self.defend(x_adv)
            with torch.no_grad():
                adv_pred_def = model(x_adv_defended).argmax(dim=1)
                adv_correct_with_defense += (adv_pred_def == y).sum().item()

        return {
            "original_accuracy": orig_correct / total,
            "adversarial_accuracy_no_defense": adv_correct_no_defense / total,
            "adversarial_accuracy_with_defense": adv_correct_with_defense / total,
            "defense_improvement": (
                (adv_correct_with_defense - adv_correct_no_defense) / total
            ),
        }