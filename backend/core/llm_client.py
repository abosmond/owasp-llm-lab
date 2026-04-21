from __future__ import annotations

import httpx
import openai
import anthropic

from core.config import settings


class LLMResponse:
    def __init__(self, content: str, provider: str, model: str):
        self.content = content
        self.provider = provider
        self.model = model

    def dict(self) -> dict:
        return {"content": self.content, "provider": self.provider, "model": self.model}


async def _call_ollama(prompt: str, system: str | None) -> LLMResponse:
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.post(
            f"{settings.ollama_host}/api/chat",
            json={"model": settings.ollama_model, "messages": messages, "stream": False},
        )
        resp.raise_for_status()
        data = resp.json()

    content = data["message"]["content"]
    return LLMResponse(content=content, provider="ollama", model=settings.ollama_model)


async def _call_openai(prompt: str, system: str | None) -> LLMResponse:
    client = openai.AsyncOpenAI(api_key=settings.openai_api_key)
    messages: list[dict] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    resp = await client.chat.completions.create(
        model=settings.openai_model,
        messages=messages,
    )
    content = resp.choices[0].message.content or ""
    return LLMResponse(content=content, provider="openai", model=settings.openai_model)


async def _call_anthropic(prompt: str, system: str | None) -> LLMResponse:
    client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)

    kwargs: dict = {
        "model": settings.anthropic_model,
        "max_tokens": 2048,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        kwargs["system"] = system

    resp = await client.messages.create(**kwargs)
    content = resp.content[0].text if resp.content else ""
    return LLMResponse(content=content, provider="anthropic", model=settings.anthropic_model)


async def chat(prompt: str, system: str | None = None) -> LLMResponse:
    """Route to the configured LLM provider."""
    provider = settings.llm_provider

    if provider == "ollama":
        return await _call_ollama(prompt, system)
    elif provider == "openai":
        return await _call_openai(prompt, system)
    elif provider == "anthropic":
        return await _call_anthropic(prompt, system)

    raise ValueError(f"Unknown LLM provider: {provider}")
