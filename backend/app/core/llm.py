"""
SecureAI Toolkit - LLM 统一调用层
支持 OpenAI API 和 Ollama 本地模型切换
"""
import json
import logging
from abc import ABC, abstractmethod
from typing import Any, AsyncIterator, Optional

import httpx
from openai import AsyncOpenAI

from app.config import settings

logger = logging.getLogger(__name__)


class BaseLLMProvider(ABC):
    """LLM 提供者基类"""

    @abstractmethod
    async def chat(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs,
    ) -> str:
        """同步对话接口"""
        pass

    @abstractmethod
    async def chat_stream(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs,
    ) -> AsyncIterator[str]:
        """流式对话接口"""
        pass

    @abstractmethod
    async def chat_with_tools(
        self,
        messages: list[dict[str, str]],
        tools: list[dict[str, Any]],
        temperature: float = 0.7,
        **kwargs,
    ) -> dict[str, Any]:
        """带工具调用的对话接口"""
        pass


class OpenAIProvider(BaseLLMProvider):
    """OpenAI API 提供者"""

    def __init__(self):
        self.client = AsyncOpenAI(
            api_key=settings.llm.openai_api_key,
            base_url=settings.llm.openai_api_base,
        )
        self.model = settings.llm.openai_model

    async def chat(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs,
    ) -> str:
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )
        return response.choices[0].message.content

    async def chat_stream(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs,
    ) -> AsyncIterator[str]:
        stream = await self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=True,
            **kwargs,
        )
        async for chunk in stream:
            if chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content

    async def chat_with_tools(
        self,
        messages: list[dict[str, str]],
        tools: list[dict[str, Any]],
        temperature: float = 0.7,
        **kwargs,
    ) -> dict[str, Any]:
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            tools=tools,
            temperature=temperature,
            **kwargs,
        )
        message = response.choices[0].message
        result = {
            "content": message.content,
            "tool_calls": [],
        }
        if message.tool_calls:
            for tc in message.tool_calls:
                result["tool_calls"].append({
                    "id": tc.id,
                    "name": tc.function.name,
                    "arguments": tc.function.arguments,
                })
        return result


class OllamaProvider(BaseLLMProvider):
    """Ollama 本地模型提供者"""

    def __init__(self):
        self.api_base = settings.llm.ollama_api_base
        self.model = settings.llm.ollama_model

    async def chat(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs,
    ) -> str:
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{self.api_base}/api/chat",
                json={
                    "model": self.model,
                    "messages": messages,
                    "stream": False,
                    "options": {
                        "temperature": temperature,
                        "num_predict": max_tokens,
                    },
                },
            )
            response.raise_for_status()
            return response.json()["message"]["content"]

    async def chat_stream(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs,
    ) -> AsyncIterator[str]:
        async with httpx.AsyncClient(timeout=120.0) as client:
            async with client.stream(
                "POST",
                f"{self.api_base}/api/chat",
                json={
                    "model": self.model,
                    "messages": messages,
                    "stream": True,
                    "options": {
                        "temperature": temperature,
                        "num_predict": max_tokens,
                    },
                },
            ) as response:
                async for line in response.aiter_lines():
                    if line:
                        data = json.loads(line)
                        if "message" in data and data["message"].get("content"):
                            yield data["message"]["content"]

    async def chat_with_tools(
        self,
        messages: list[dict[str, str]],
        tools: list[dict[str, Any]],
        temperature: float = 0.7,
        **kwargs,
    ) -> dict[str, Any]:
        # Ollama 工具调用支持（需模型支持）
        content = await self.chat(messages, temperature=temperature, **kwargs)
        return {
            "content": content,
            "tool_calls": [],
        }


class LLMRouter:
    """LLM 路由器 - 根据 provider 选择对应实现"""

    def __init__(self):
        self._providers: dict[str, BaseLLMProvider] = {}

    def get_provider(self, provider_name: Optional[str] = None) -> BaseLLMProvider:
        name = provider_name or settings.llm.default_provider
        if name not in self._providers:
            if name == "openai":
                self._providers[name] = OpenAIProvider()
            elif name == "ollama":
                self._providers[name] = OllamaProvider()
            else:
                raise ValueError(f"Unknown LLM provider: {name}")
        return self._providers[name]

    async def chat(
        self,
        messages: list[dict[str, str]],
        provider: Optional[str] = None,
        **kwargs,
    ) -> str:
        p = self.get_provider(provider)
        return await p.chat(messages, **kwargs)

    async def chat_stream(
        self,
        messages: list[dict[str, str]],
        provider: Optional[str] = None,
        **kwargs,
    ) -> AsyncIterator[str]:
        p = self.get_provider(provider)
        async for chunk in p.chat_stream(messages, **kwargs):
            yield chunk

    async def chat_with_tools(
        self,
        messages: list[dict[str, str]],
        tools: list[dict[str, Any]],
        provider: Optional[str] = None,
        **kwargs,
    ) -> dict[str, Any]:
        p = self.get_provider(provider)
        return await p.chat_with_tools(messages, tools, **kwargs)


# 全局单例
llm_router = LLMRouter()
