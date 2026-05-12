"""
ThreatLens - AutoEncoder 异常检测模型
基于自编码器的网络流量异常检测
"""
import logging
from pathlib import Path
from typing import Optional

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset

logger = logging.getLogger(__name__)


class AutoEncoderModel(nn.Module):
    """自编码器模型 - 用于异常检测"""

    def __init__(self, input_dim: int = 37, hidden_dims: Optional[list[int]] = None):
        super().__init__()

        if hidden_dims is None:
            hidden_dims = [32, 16, 8]

        # 编码器
        encoder_layers = []
        prev_dim = input_dim
        for hidden_dim in hidden_dims:
            encoder_layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.BatchNorm1d(hidden_dim),
                nn.ReLU(),
            ])
            prev_dim = hidden_dim
        self.encoder = nn.Sequential(*encoder_layers)

        # 解码器（镜像结构）
        decoder_layers = []
        for hidden_dim in reversed(hidden_dims):
            decoder_layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.BatchNorm1d(hidden_dim),
                nn.ReLU(),
            ])
            prev_dim = hidden_dim
        decoder_layers.append(nn.Linear(prev_dim, input_dim))
        self.decoder = nn.Sequential(*decoder_layers)

        self.latent_dim = hidden_dims[-1]

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        latent = self.encoder(x)
        reconstructed = self.decoder(latent)
        return reconstructed, latent

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        return self.encoder(x)

    def decode(self, z: torch.Tensor) -> torch.Tensor:
        return self.decoder(z)


class AutoEncoderDetector:
    """基于 AutoEncoder 的异常检测器"""

    def __init__(
        self,
        input_dim: int = 37,
        hidden_dims: Optional[list[int]] = None,
        threshold_percentile: float = 95.0,
        device: str = "auto",
    ):
        if device == "auto":
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
        else:
            self.device = device

        self.model = AutoEncoderModel(input_dim, hidden_dims).to(self.device)
        self.threshold_percentile = threshold_percentile
        self.threshold: Optional[float] = None
        self.is_trained = False

    def train(
        self,
        X_train: np.ndarray,
        epochs: int = 50,
        batch_size: int = 64,
        learning_rate: float = 1e-3,
        validation_split: float = 0.1,
    ) -> dict[str, list[float]]:
        """
        训练自编码器（仅使用正常流量数据）
        """
        self.model.train()

        # 准备数据
        X_tensor = torch.FloatTensor(X_train).to(self.device)
        dataset = TensorDataset(X_tensor)
        dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

        optimizer = optim.Adam(self.model.parameters(), lr=learning_rate)
        criterion = nn.MSELoss()

        # 分割验证集
        n_val = int(len(X_tensor) * validation_split)
        X_val = X_tensor[:n_val]
        X_train_tensor = X_tensor[n_val:]

        train_losses = []
        val_losses = []

        for epoch in range(epochs):
            epoch_loss = 0.0
            n_batches = 0

            for (batch,) in dataloader:
                optimizer.zero_grad()
                reconstructed, _ = self.model(batch)
                loss = criterion(reconstructed, batch)
                loss.backward()
                optimizer.step()

                epoch_loss += loss.item()
                n_batches += 1

            avg_train_loss = epoch_loss / max(n_batches, 1)
            train_losses.append(avg_train_loss)

            # 验证
            self.model.eval()
            with torch.no_grad():
                val_reconstructed, _ = self.model(X_val)
                val_loss = criterion(val_reconstructed, X_val).item()
                val_losses.append(val_loss)
            self.model.train()

            if (epoch + 1) % 10 == 0:
                logger.info(
                    f"Epoch {epoch+1}/{epochs} - "
                    f"Train Loss: {avg_train_loss:.6f}, Val Loss: {val_loss:.6f}"
                )

        # 计算异常阈值
        self.model.eval()
        with torch.no_grad():
            all_reconstructed, _ = self.model(X_tensor)
            reconstruction_errors = torch.mean((all_reconstructed - X_tensor) ** 2, dim=1)
            self.threshold = float(np.percentile(
                reconstruction_errors.cpu().numpy(),
                self.threshold_percentile,
            ))

        self.is_trained = True
        logger.info(f"Training complete. Threshold: {self.threshold:.6f}")

        return {"train_losses": train_losses, "val_losses": val_losses}

    def predict(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """
        预测是否为异常流量
        Returns: (is_anomaly, anomaly_scores)
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained. Call train() first.")

        self.model.eval()
        X_tensor = torch.FloatTensor(X).to(self.device)

        with torch.no_grad():
            reconstructed, _ = self.model(X_tensor)
            reconstruction_errors = torch.mean((reconstructed - X_tensor) ** 2, dim=1)
            scores = reconstruction_errors.cpu().numpy()

        is_anomaly = scores > self.threshold
        return is_anomaly, scores

    def get_anomaly_score(self, x: np.ndarray) -> float:
        """获取单条记录的异常分数"""
        is_anomaly, scores = self.predict(x.reshape(1, -1))
        return float(scores[0])

    def save(self, path: str):
        """保存模型"""
        save_dict = {
            "model_state": self.model.state_dict(),
            "threshold": self.threshold,
            "is_trained": self.is_trained,
        }
        torch.save(save_dict, path)
        logger.info(f"Model saved to {path}")

    def load(self, path: str):
        """加载模型"""
        save_dict = torch.load(path, map_location=self.device)
        self.model.load_state_dict(save_dict["model_state"])
        self.threshold = save_dict["threshold"]
        self.is_trained = save_dict["is_trained"]
        logger.info(f"Model loaded from {path}, threshold={self.threshold}")