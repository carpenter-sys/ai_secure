"""
SecureAI Toolkit - 配置管理模块
支持从环境变量和 .env 文件加载配置
"""
import os
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings
from pydantic import Field


class LLMConfig(BaseSettings):
    """LLM API 配置"""
    openai_api_key: str = Field(default="", alias="OPENAI_API_KEY")
    openai_api_base: str = Field(default="https://api.openai.com/v1", alias="OPENAI_API_BASE")
    openai_model: str = Field(default="gpt-4o", alias="OPENAI_MODEL")
    ollama_api_base: str = Field(default="http://localhost:11434", alias="OLLAMA_API_BASE")
    ollama_model: str = Field(default="llama3", alias="OLLAMA_MODEL")
    # 默认使用 openai 还是 ollama
    default_provider: str = "openai"

    model_config = {"env_file": ".env", "extra": "ignore"}


class DatabaseConfig(BaseSettings):
    """数据库配置"""
    postgres_host: str = Field(default="localhost", alias="POSTGRES_HOST")
    postgres_port: int = Field(default=5432, alias="POSTGRES_PORT")
    postgres_user: str = Field(default="secureai", alias="POSTGRES_USER")
    postgres_password: str = Field(default="secureai_dev_2024", alias="POSTGRES_PASSWORD")
    postgres_db: str = Field(default="secureai", alias="POSTGRES_DB")
    redis_host: str = Field(default="localhost", alias="REDIS_HOST")
    redis_port: int = Field(default=6379, alias="REDIS_PORT")
    redis_password: str = Field(default="", alias="REDIS_PASSWORD")
    milvus_host: str = Field(default="localhost", alias="MILVUS_HOST")
    milvus_port: int = Field(default=19530, alias="MILVUS_PORT")

    model_config = {"env_file": ".env", "extra": "ignore"}

    @property
    def postgres_dsn(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def redis_dsn(self) -> str:
        if self.redis_password:
            return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}"
        return f"redis://{self.redis_host}:{self.redis_port}"


class AppConfig(BaseSettings):
    """应用全局配置"""
    app_host: str = Field(default="0.0.0.0", alias="APP_HOST")
    app_port: int = Field(default=8000, alias="APP_PORT")
    app_debug: bool = Field(default=True, alias="APP_DEBUG")
    app_secret_key: str = Field(default="change-me-in-production", alias="APP_SECRET_KEY")
    mlflow_tracking_uri: str = Field(default="http://localhost:5000", alias="MLFLOW_TRACKING_URI")

    model_config = {"env_file": ".env", "extra": "ignore"}


class Settings:
    """全局设置聚合"""
    def __init__(self):
        self.llm = LLMConfig()
        self.db = DatabaseConfig()
        self.app = AppConfig()

    def reload(self):
        """重新加载配置"""
        self.llm = LLMConfig()
        self.db = DatabaseConfig()
        self.app = AppConfig()


# 全局单例
settings = Settings()
