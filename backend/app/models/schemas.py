"""
SecureAI Toolkit - 数据模型定义
"""
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ===== 通用枚举 =====

class CTFCategory(str, Enum):
    WEB = "web"
    PWN = "pwn"
    REVERSE = "reverse"
    CRYPTO = "crypto"
    MISC = "misc"
    FORENSICS = "forensics"


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class LLMProvider(str, Enum):
    OPENAI = "openai"
    OLLAMA = "ollama"


# ===== CTF-AutoSolver 模型 =====

class CTFChallenge(BaseModel):
    """CTF题目"""
    id: Optional[str] = None
    title: str
    description: str
    category: CTFCategory
    url: Optional[str] = None
    attachment_paths: list[str] = Field(default_factory=list)
    hints: list[str] = Field(default_factory=list)
    points: Optional[int] = None


class CTFSolution(BaseModel):
    """CTF解题结果"""
    challenge_id: str
    category: CTFCategory
    analysis: str
    strategy: str
    payload: Optional[str] = None
    flag: Optional[str] = None
    tools_used: list[str] = Field(default_factory=list)
    steps: list[dict[str, Any]] = Field(default_factory=list)
    confidence: float = 0.0


class CTFSolveRequest(BaseModel):
    """CTF解题请求"""
    challenge: CTFChallenge
    provider: LLMProvider = LLMProvider.OPENAI
    auto_execute: bool = False  # 是否自动执行payload


class CTFSolveResponse(BaseModel):
    """CTF解题响应"""
    task_id: str
    status: TaskStatus
    solution: Optional[CTFSolution] = None
    error: Optional[str] = None


# ===== LLM-Guard 模型 =====

class AttackType(str, Enum):
    PROMPT_INJECTION_DIRECT = "prompt_injection_direct"
    PROMPT_INJECTION_INDIRECT = "prompt_injection_indirect"
    PROMPT_INJECTION_MULTI_TURN = "prompt_injection_multi_turn"
    JAILBREAK_GCG = "jailbreak_gcg"
    JAILBREAK_PAIR = "jailbreak_pair"
    JAILBREAK_AUTODAN = "jailbreak_autodan"
    JAILBREAK_TEMPLATE = "jailbreak_template"


class LLMTarget(BaseModel):
    """LLM攻击目标"""
    name: str
    provider: LLMProvider
    model: str
    api_base: Optional[str] = None
    api_key: Optional[str] = None


class AttackRequest(BaseModel):
    """攻击请求"""
    target: LLMTarget
    attack_types: list[AttackType]
    num_variations: int = 5
    categories: list[str] = Field(
        default_factory=lambda: [
            "politics", "violence", "privacy_leak",
            "harmful_instruction", "bias"
        ]
    )


class AttackResult(BaseModel):
    """单次攻击结果"""
    attack_type: AttackType
    prompt: str
    response: str
    is_harmful: bool
    harm_score: float  # 0.0 - 1.0
    category: str


class SecurityReport(BaseModel):
    """安全评估报告"""
    target_name: str
    target_model: str
    timestamp: datetime
    total_attacks: int
    successful_attacks: int
    attack_success_rate: float
    results: list[AttackResult]
    recommendations: list[str]


# ===== ThreatLens 模型 =====

class TrafficFeatures(BaseModel):
    """网络流量特征"""
    flow_id: Optional[str] = None
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    flow_duration: float
    total_fwd_packets: int
    total_bwd_packets: int
    fwd_packet_len_mean: float
    bwd_packet_len_mean: float
    extra_features: dict[str, float] = Field(default_factory=dict)


class ThreatDetectionResult(BaseModel):
    """威胁检测结果"""
    flow_id: str
    is_threat: bool
    threat_type: Optional[str] = None
    confidence: float
    model_name: str
    features_used: list[str]
    timestamp: datetime


class ThreatDetectionRequest(BaseModel):
    """威胁检测请求"""
    features: list[TrafficFeatures]
    model_name: str = "autoencoder"
    threshold: float = 0.95


# ===== AdverLab 模型 =====

class AdversarialAttackType(str, Enum):
    FGSM = "fgsm"
    PGD = "pgd"
    CW = "cw"
    TRANSFER = "transfer"
    QUERY_BASED = "query_based"


class DefenseType(str, Enum):
    ADVERSARIAL_TRAINING = "adversarial_training"
    INPUT_PREPROCESSING = "input_preprocessing"
    DETECTION = "detection"
    CERTIFIED_ROBUSTNESS = "certified_robustness"


class ExperimentConfig(BaseModel):
    """实验配置"""
    name: str
    attack_type: AdversarialAttackType
    defense_type: Optional[DefenseType] = None
    dataset: str = "mnist"
    model_architecture: str = "resnet18"
    epsilon: float = 0.03
    attack_params: dict[str, Any] = Field(default_factory=dict)
    defense_params: dict[str, Any] = Field(default_factory=dict)


class ExperimentResult(BaseModel):
    """实验结果"""
    experiment_name: str
    original_accuracy: float
    adversarial_accuracy: float
    robust_accuracy: Optional[float] = None
    attack_success_rate: float
    perturbation_norm: float
    config: ExperimentConfig
    timestamp: datetime
