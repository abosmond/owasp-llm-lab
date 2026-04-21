from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator
from typing import Literal


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # App
    app_title: str = "OWASP LLM Lab"
    environment: Literal["development", "production"] = "development"
    secret_key: str = "change-me"

    # LLM provider selection
    llm_provider: Literal["ollama", "openai", "anthropic"] = "ollama"

    # Ollama (host machine via host.docker.internal)
    ollama_host: str = "http://host.docker.internal:11434"
    ollama_model: str = "llama3:latest"

    # OpenAI
    openai_api_key: str = ""
    openai_model: str = "gpt-4o"

    # Anthropic
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-6"

    # CORS
    cors_origins: str = "http://localhost"

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors(cls, v: str) -> str:
        return v

    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
