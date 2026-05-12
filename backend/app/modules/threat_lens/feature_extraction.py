"""
ThreatLens - 网络流量特征提取模块
支持从网络流量数据和日志中提取安全相关特征
"""
import logging
from typing import Any, Optional

import numpy as np

from app.models.schemas import TrafficFeatures

logger = logging.getLogger(__name__)


class FlowFeatureExtractor:
    """网络流特征提取器"""

    # 默认特征列名
    DEFAULT_FEATURE_COLUMNS = [
        "flow_duration",
        "total_fwd_packets",
        "total_bwd_packets",
        "fwd_packet_len_mean",
        "bwd_packet_len_mean",
        "fwd_packet_len_std",
        "bwd_packet_len_std",
        "fwd_packet_len_max",
        "bwd_packet_len_max",
        "fwd_packet_len_min",
        "bwd_packet_len_min",
        "flow_bytes_per_sec",
        "flow_packets_per_sec",
        "fwd_iat_mean",
        "bwd_iat_mean",
        "fwd_iat_std",
        "bwd_iat_std",
        "fwd_psh_flags",
        "bwd_psh_flags",
        "fwd_urg_flags",
        "bwd_urg_flags",
        "fwd_header_length",
        "bwd_header_length",
        "pkt_len_mean",
        "pkt_len_std",
        "pkt_len_var",
        "fin_flag_count",
        "syn_flag_count",
        "rst_flag_count",
        "psh_flag_count",
        "ack_flag_count",
        "urg_flag_count",
        "cwe_flag_count",
        "ece_flag_count",
        "down_up_ratio",
        "init_fwd_win_bytes",
        "init_bwd_win_bytes",
    ]

    def extract(self, flow: TrafficFeatures) -> np.ndarray:
        """
        从单条流量记录提取特征向量
        """
        features = [
            flow.flow_duration,
            flow.total_fwd_packets,
            flow.total_bwd_packets,
            flow.fwd_packet_len_mean,
            flow.bwd_packet_len_mean,
        ]

        # 添加 extra_features 中的特征
        for col in self.DEFAULT_FEATURE_COLUMNS[5:]:
            features.append(flow.extra_features.get(col, 0.0))

        return np.array(features, dtype=np.float32)

    def extract_batch(self, flows: list[TrafficFeatures]) -> np.ndarray:
        """批量提取特征"""
        return np.array([self.extract(flow) for flow in flows], dtype=np.float32)

    @staticmethod
    def compute_statistical_features(values: list[float]) -> dict[str, float]:
        """计算统计特征"""
        if not values:
            return {"mean": 0.0, "std": 0.0, "max": 0.0, "min": 0.0, "var": 0.0}

        arr = np.array(values, dtype=np.float32)
        return {
            "mean": float(np.mean(arr)),
            "std": float(np.std(arr)),
            "max": float(np.max(arr)),
            "min": float(np.min(arr)),
            "var": float(np.var(arr)),
        }


class LogFeatureExtractor:
    """日志特征提取器"""

    # 常见攻击模式关键词
    ATTACK_PATTERNS = {
        "sql_injection": [
            "union select", "or 1=1", "' or '", "drop table",
            "information_schema", "sleep(", "benchmark(",
        ],
        "xss": [
            "<script>", "onerror=", "onload=", "javascript:",
            "alert(", "document.cookie",
        ],
        "path_traversal": [
            "../", "..\\", "/etc/passwd", "/proc/self",
            "php://filter", "file:///",
        ],
        "brute_force": [
            "failed login", "authentication failure", "invalid password",
            "login attempt", "access denied",
        ],
        "command_injection": [
            "; cat ", "| ls", "`whoami`", "$(id)",
            "& whoami", "/bin/sh", "/bin/bash",
        ],
    }

    # 日志级别权重
    SEVERITY_WEIGHTS = {
        "CRITICAL": 1.0,
        "ERROR": 0.8,
        "WARNING": 0.6,
        "INFO": 0.2,
        "DEBUG": 0.1,
    }

    def extract(self, log_entry: str) -> dict[str, Any]:
        """
        从日志条目提取特征
        """
        log_lower = log_entry.lower()

        # 检测攻击模式
        detected_patterns: dict[str, list[str]] = {}
        for attack_type, patterns in self.ATTACK_PATTERNS.items():
            matches = [p for p in patterns if p.lower() in log_lower]
            if matches:
                detected_patterns[attack_type] = matches

        # 提取日志级别
        severity = "INFO"
        for level in self.SEVERITY_WEIGHTS:
            if level in log_entry.upper():
                severity = level
                break

        # 计算特征
        features = {
            "length": len(log_entry),
            "severity": severity,
            "severity_weight": self.SEVERITY_WEIGHTS.get(severity, 0.2),
            "detected_attacks": detected_patterns,
            "attack_type_count": len(detected_patterns),
            "has_ip": bool(self._extract_ip(log_entry)),
            "has_url": bool(self._extract_url(log_entry)),
            "has_error_keyword": any(
                kw in log_lower for kw in ["error", "fail", "exception", "denied", "unauthorized"]
            ),
        }

        return features

    def extract_batch(self, log_entries: list[str]) -> list[dict[str, Any]]:
        """批量提取日志特征"""
        return [self.extract(entry) for entry in log_entries]

    def to_feature_vector(self, features: dict[str, Any]) -> np.ndarray:
        """将提取的特征转换为向量"""
        vector = [
            features["length"],
            features["severity_weight"],
            features["attack_type_count"],
            float(features["has_ip"]),
            float(features["has_url"]),
            float(features["has_error_keyword"]),
        ]

        # 攻击类型 one-hot 编码
        for attack_type in self.ATTACK_PATTERNS:
            vector.append(float(attack_type in features["detected_attacks"]))

        return np.array(vector, dtype=np.float32)

    @staticmethod
    def _extract_ip(text: str) -> Optional[str]:
        import re
        pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        match = re.search(pattern, text)
        return match.group(0) if match else None

    @staticmethod
    def _extract_url(text: str) -> Optional[str]:
        import re
        pattern = r"https?://[^\s<>\"]+"
        match = re.search(pattern, text)
        return match.group(0) if match else None