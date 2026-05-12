"""
ThreatLens - API 路由
"""
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, UploadFile, File

from app.models.schemas import (
    ThreatDetectionRequest,
    ThreatDetectionResult,
    TrafficFeatures,
)
from .detector import threat_engine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/threat-lens", tags=["ThreatLens"])


@router.post("/detect", response_model=list[ThreatDetectionResult])
async def detect_threats(request: ThreatDetectionRequest):
    """检测网络流量中的威胁"""
    results = await threat_engine.detect(request)
    return results


@router.post("/detect/single")
async def detect_single_flow(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: str = "TCP",
    flow_duration: float = 0.0,
    total_fwd_packets: int = 0,
    total_bwd_packets: int = 0,
    fwd_packet_len_mean: float = 0.0,
    bwd_packet_len_mean: float = 0.0,
    model_name: str = "autoencoder",
    threshold: float = 0.95,
):
    """检测单条流量记录"""
    flow = TrafficFeatures(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        flow_duration=flow_duration,
        total_fwd_packets=total_fwd_packets,
        total_bwd_packets=total_bwd_packets,
        fwd_packet_len_mean=fwd_packet_len_mean,
        bwd_packet_len_mean=bwd_packet_len_mean,
    )

    request = ThreatDetectionRequest(
        features=[flow],
        model_name=model_name,
        threshold=threshold,
    )
    results = await threat_engine.detect(request)
    return results[0] if results else {}


@router.get("/models/status")
async def get_model_status():
    """获取检测模型状态"""
    return threat_engine.get_model_status()


@router.post("/train/{model_name}")
async def train_model(
    model_name: str,
    dataset_path: str,
    epochs: int = 50,
    learning_rate: float = 1e-3,
):
    """训练检测模型（提供数据集路径）"""
    import numpy as np

    try:
        # 加载 CSV 数据集
        import pandas as pd
        df = pd.read_csv(dataset_path)

        # 分离特征和标签
        label_col = None
        for col in ["label", "Label", "class", "Class", "target"]:
            if col in df.columns:
                label_col = col
                break

        if label_col is None:
            raise HTTPException(status_code=400, detail="No label column found in dataset")

        X = df.drop(columns=[label_col]).select_dtypes(include=[np.number]).values
        y = df[label_col].values

        # 训练
        model = threat_engine.models.get(model_name)
        if not model:
            raise HTTPException(status_code=404, detail=f"Model {model_name} not found")

        if model_name == "autoencoder":
            # 仅使用正常流量训练
            normal_mask = y == 0 if len(np.unique(y)) <= 2 else y == "BENIGN"
            X_normal = X[normal_mask] if normal_mask.any() else X
            result = model.train(X_normal, epochs=epochs, learning_rate=learning_rate)
        else:
            # 分类模型使用所有数据
            from sklearn.preprocessing import LabelEncoder
            le = LabelEncoder()
            y_encoded = le.fit_transform(y)
            result = model.train(X, y_encoded, epochs=epochs, learning_rate=learning_rate)

        return {"status": "trained", "model": model_name, "result": result}

    except Exception as e:
        logger.error(f"Training error: {e}")
        raise HTTPException(status_code=500, detail=str(e))