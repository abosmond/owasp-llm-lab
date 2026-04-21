from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from core.config import settings
from core.llm_client import chat

from scenarios.s01_direct            import router as s01_router
from scenarios.s02_indirect          import router as s02_router
from scenarios.s03_unintentional     import router as s03_router
from scenarios.s04_rag_poisoning     import router as s04_router
from scenarios.s05_code_injection    import router as s05_router
from scenarios.s06_payload_splitting import router as s06_router
from scenarios.s07_multimodal        import router as s07_router
from scenarios.s08_adversarial_suffix import router as s08_router
from scenarios.s09_multilingual      import router as s09_router

app = FastAPI(
    title=settings.app_title,
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Schemas ────────────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    message: str = Field(
        ...,
        description="User message to send to the LLM.",
        examples=["Explain prompt injection in simple terms."],
    )
    system: str = Field(
        default="",
        description="Optional system prompt that sets the LLM's behaviour. Leave empty to use the model's default.",
        examples=["You are a security researcher assistant."],
    )


class ChatResponse(BaseModel):
    content: str = Field(description="The LLM's reply.")
    provider: str = Field(description="Active LLM provider (ollama | openai | anthropic).")
    model: str = Field(description="Model name used for this response.")


# ─── Routes ─────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "provider": settings.llm_provider}


@app.post("/api/chat", response_model=ChatResponse)
async def chat_endpoint(req: ChatRequest):
    if not req.message.strip():
        raise HTTPException(status_code=422, detail="message must not be empty")
    try:
        result = await chat(req.message, req.system or None)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return ChatResponse(**result.dict())


# ─── Scenario routers ───────────────────────────────────────────────────────

app.include_router(s01_router)
app.include_router(s02_router)
app.include_router(s03_router)
app.include_router(s04_router)
app.include_router(s05_router)
app.include_router(s06_router)
app.include_router(s07_router)
app.include_router(s08_router)
app.include_router(s09_router)


@app.get("/api/config")
async def get_config():
    """Return non-sensitive runtime config (useful for the UI)."""
    return {
        "provider": settings.llm_provider,
        "model": {
            "ollama": settings.ollama_model,
            "openai": settings.openai_model,
            "anthropic": settings.anthropic_model,
        }[settings.llm_provider],
        "environment": settings.environment,
    }
