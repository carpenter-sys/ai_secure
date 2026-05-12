"""
ThreatLens - 统一检测引擎
整合异常检测和分类检测，提供统一接口
"""
import logging
from datetime import datetime
from typing import Any, Optional

import numpy as np

from app.core.llm import llm_router
from app.models.schemas import (
    ThreatDetectionRequest,
    ThreatDetectionResult,
    TrafficFeatures,
)
from .feature_extraction import FlowFeatureExtractor, LogFeatureExtractor
from .models.autoencoder import AutoEncoderDetector
from .models.classifier import LightGBMClassifier, CNN1DClassifier

logger = logging.getLogger(__name__)


class ThreatDetectionEngine:
    """威胁检测引擎"""

    def __init__(self, default_model: str = "autoencoder"):
        self.flow_extractor = FlowFeatureExtractor()
        self.log_extractor = LogFeatureExtractor()
        self.models: dict[str, Any] = {}
        self.default_model = default_model

        # 初始化模型
        self._init_models()

    def _init_models(self):
        """初始化所有检测模型"""
        self.models["autoencoder"] = AutoEncoderDetector()
        self.models["lightgbm"] = LightGBMClassifier()
        self.models["cnn1d"] = CNN1DClassifier()
        logger.info("All detection models initialized")

    async def detect(
        self,
        request: ThreatDetectionRequest,
    ) -> list[ThreatDetectionResult]:
        """
        对流量数据进行威胁检测
        """
        model_name = request.model_name
        if model_name not in self.models:
            model_name = self.default_model

        model = self.models[model_name]

        if not model.is_trained:
            return [
                ThreatDetectionResult(
                    flow_id=f.id or f"flow_{i}",
                    is_threat=False,
                    threat_type=None,
                    confidence=0.0,
                    model_name=model_name,
                    features_used=[],
                    timestamp=datetime.now(),
                )
                for i, f in enumerate(request.features)
            ]

        # 提取特征
        features = self.flow_extractor.extract_batch(request.features)

        # 模型推理
        if model_name == "autoencoder":
            is_anomaly, scores = model.predict(features)
            results = []
            for i, (flow, anomaly, score) in enumerate(
                zip(request.features, is_anomaly, scores)
            ):
                # 如果检测到异常，使用 LLM 辅助分析
                threat_type = None
                if anomaly:
                    threat_type = await self._classify_threat_llm(flow, score)

                results.append(ThreatDetectionResult(
                    flow_id=flow.id or f"flow_{i}",
                    is_threat=bool(anomaly),
                    threat_type=threat_type,
                    confidence=float(score),
                    model_name=model_name,
                    features_used=self.flow_extractor.DEFAULT_FEATURE_COLUMNS[:10],
                    timestamp=datetime.now(),
                ))
            return results

        else:
            predictions = model.predict(features)
            probas = model.predict_proba(features)
            results = []
            for i, (flow, pred, proba) in enumerate(
                zip(request.features, predictions, probas)
            ):
                confidence = float(np.max(proba))
                threat_type = self._label_to_name(pred) if confidence > request.threshold else None

                results.append(ThreatDetectionResult(
                    flow_id=flow.id or f"flow_{i}",
                    is_threat=confidence > request.threshold,
                    threat_type=threat_type,
                    confidence=confidence,
                    model_name=model_name,
                    features_used=self.flow_extractor.DEFAULT_FEATURE_COLUMNS[:10],
                    timestamp=datetime.now(),
                ))
            return results

    async def _classify_threat_llm(
        self, flow: TrafficFeatures, score: float
    ) -> str:
        """使用 LLM 辅助分类威胁类型"""
        try:
            result = await llm_router.chat(
                messages=[{
                    "role": "user",
                    "content": (
                        f"Classify this network anomaly as one of: "
                        f"DDoS, Port Scan, Brute Force, Data Exfiltration, "
                        f"Malware C2, SQL Injection, XSS, Other.\n\n"
                        f"Flow details:\n"
                        f"- Src: {flow.src_ip}:{flow.src_port}\n"
                        f"- Dst: {flow.dst_ip}:{flow.dst_port}\n"
                        f"- Protocol: {flow.protocol}\n"
                        f"- Duration: {flow.flow_duration}\n"
                        f"- Fwd packets: {flow.total_fwd_packets}\n"
                        f"- Bwd packets: {flow.total_bwd_packets}\n"
                        f"- Anomaly score: {score:.4f}\n\n"
                        f"Respond with ONLY the threat type name."
                    ),
                }],
                temperature=0.1,
                max_tokens=20,
            )
            return result.strip()
        except Exception:
            return "Unknown"

    @staticmethod
    def _label_to_name(label: int) -> str:
        """标签编号转名称"""
        names = {
            0: "Benign",
            1: "DDoS",
            2: "Port Scan",
            3: "Brute Force",
            4: "Data Exfiltration",
            5: "Malware C2",
            6: "SQL Injection",
            7: "XSS",
            8: "Fuzzing",
            9: "Other",
        }
        return names.get(label, "Unknown")

    def get_model_status(self) -> dict[str, Any]:
        """获取所有模型状态"""
        return {
            name: {
                "is_trained": getattr(model, "is_trained", False),
                "type": type(model).__name__,
            }
            for name, model in self.models.items()
        }


# 全局单例
threat_engine = ThreatDetectionEngine()