"""
ThreatLens - 分类检测模型
基于 LightGBM / 1D-CNN 的威胁分类器
"""
import logging
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)


class LightGBMClassifier:
    """基于 LightGBM 的威胁分类器"""

    def __init__(self, num_classes: int = 10, **kwargs):
        self.num_classes = num_classes
        self.model = None
        self.is_trained = False
        self.label_names: list[str] = []
        self.params = {
            "objective": "multiclass" if num_classes > 2 else "binary",
            "num_class": num_classes if num_classes > 2 else None,
            "metric": "multi_logloss" if num_classes > 2 else "binary_logloss",
            "boosting_type": "gbdt",
            "num_leaves": 31,
            "learning_rate": 0.05,
            "feature_fraction": 0.9,
            "verbose": -1,
        }
        self.params.update(kwargs)

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        num_iterations: int = 200,
    ) -> dict:
        """训练分类器"""
        try:
            import lightgbm as lgb
        except ImportError:
            logger.warning("LightGBM not installed, falling back to sklearn")
            return self._train_sklearn_fallback(X_train, y_train)

        train_data = lgb.Dataset(X_train, label=y_train)
        valid_data = None
        if X_val is not None and y_val is not None:
            valid_data = lgb.Dataset(X_val, label=y_val, reference=train_data)

        callbacks = [lgb.log_evaluation(period=50)]
        self.model = lgb.train(
            self.params,
            train_data,
            num_iterations,
            valid_sets=[valid_data] if valid_data else None,
            callbacks=callbacks,
        )
        self.is_trained = True

        return {"status": "trained", "iterations": num_iterations}

    def _train_sklearn_fallback(self, X_train: np.ndarray, y_train: np.ndarray) -> dict:
        """使用 sklearn 作为后备"""
        from sklearn.ensemble import GradientBoostingClassifier
        self.model = GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.05,
            max_depth=5,
        )
        self.model.fit(X_train, y_train)
        self.is_trained = True
        return {"status": "trained (sklearn fallback)"}

    def predict(self, X: np.ndarray) -> np.ndarray:
        """预测类别"""
        if not self.is_trained:
            raise RuntimeError("Model not trained")
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """预测概率"""
        if not self.is_trained:
            raise RuntimeError("Model not trained")
        return self.model.predict_proba(X)

    def feature_importance(self) -> Optional[np.ndarray]:
        """获取特征重要性"""
        if not self.is_trained:
            return None
        try:
            import lightgbm as lgb
            return self.model.feature_importance()
        except (ImportError, AttributeError):
            try:
                return self.model.feature_importances_
            except AttributeError:
                return None


class CNN1DClassifier:
    """基于 1D-CNN 的威胁分类器"""

    def __init__(
        self,
        input_dim: int = 37,
        num_classes: int = 10,
        device: str = "auto",
    ):
        import torch
        import torch.nn as nn

        if device == "auto":
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
        else:
            self.device = device

        self.input_dim = input_dim
        self.num_classes = num_classes
        self.model = self._build_model()
        self.is_trained = False

    def _build_model(self):
        import torch.nn as nn

        class ThreatCNN(nn.Module):
            def __init__(self, input_dim, num_classes):
                super().__init__()
                self.features = nn.Sequential(
                    nn.Conv1d(1, 32, kernel_size=3, padding=1),
                    nn.BatchNorm1d(32),
                    nn.ReLU(),
                    nn.MaxPool1d(2),
                    nn.Conv1d(32, 64, kernel_size=3, padding=1),
                    nn.BatchNorm1d(64),
                    nn.ReLU(),
                    nn.MaxPool1d(2),
                    nn.AdaptiveAvgPool1d(1),
                )
                self.classifier = nn.Sequential(
                    nn.Linear(64, 32),
                    nn.ReLU(),
                    nn.Dropout(0.3),
                    nn.Linear(32, num_classes),
                )

            def forward(self, x):
                x = x.unsqueeze(1)
                x = self.features(x)
                x = x.view(x.size(0), -1)
                x = self.classifier(x)
                return x

        return ThreatCNN(self.input_dim, self.num_classes).to(self.device)

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        epochs: int = 30,
        batch_size: int = 64,
        learning_rate: float = 1e-3,
    ) -> dict:
        import torch
        import torch.nn as nn
        import torch.optim as optim
        from torch.utils.data import DataLoader, TensorDataset

        self.model.train()
        X_tensor = torch.FloatTensor(X_train).to(self.device)
        y_tensor = torch.LongTensor(y_train).to(self.device)
        dataset = TensorDataset(X_tensor, y_tensor)
        dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

        optimizer = optim.Adam(self.model.parameters(), lr=learning_rate)
        criterion = nn.CrossEntropyLoss()

        losses = []
        for epoch in range(epochs):
            epoch_loss = 0.0
            for batch_X, batch_y in dataloader:
                optimizer.zero_grad()
                output = self.model(batch_X)
                loss = criterion(output, batch_y)
                loss.backward()
                optimizer.step()
                epoch_loss += loss.item()
            avg_loss = epoch_loss / len(dataloader)
            losses.append(avg_loss)

            if (epoch + 1) % 10 == 0:
                logger.info(f"CNN Epoch {epoch+1}/{epochs}, Loss: {avg_loss:.4f}")

        self.is_trained = True
        return {"train_losses": losses}

    def predict(self, X: np.ndarray) -> np.ndarray:
        import torch
        if not self.is_trained:
            raise RuntimeError("Model not trained")
        self.model.eval()
        X_tensor = torch.FloatTensor(X).to(self.device)
        with torch.no_grad():
            output = self.model(X_tensor)
            predictions = torch.argmax(output, dim=1)
        return predictions.cpu().numpy()

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        import torch
        import torch.nn.functional as F
        if not self.is_trained:
            raise RuntimeError("Model not trained")
        self.model.eval()
        X_tensor = torch.FloatTensor(X).to(self.device)
        with torch.no_grad():
            output = self.model(X_tensor)
            probs = F.softmax(output, dim=1)
        return probs.cpu().numpy()

    def save(self, path: str):
        import torch
        torch.save({"model_state": self.model.state_dict()}, path)

    def load(self, path: str):
        import torch
        checkpoint = torch.load(path, map_location=self.device)
        self.model.load_state_dict(checkpoint["model_state"])
        self.is_trained = True