# OWASP LLM Lab

A sandboxed lab environment for exploring and demonstrating [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) vulnerabilities.

## Stack

| Layer    | Technology                          |
|----------|-------------------------------------|
| Backend  | Python 3.12 / FastAPI               |
| Frontend | Vanilla HTML/JS (served via Nginx)  |
| Proxy    | Nginx                               |
| LLM      | Ollama (local) · OpenAI · Anthropic |

## Quick Start

```bash
# 1. Copy and configure environment
cp .env.example .env
# edit .env — set LLM_PROVIDER and the matching API key / model

# 2. Start services
docker compose up --build

# 3. Open the lab
open http://localhost
```

API docs are available at `http://localhost/docs`.

## LLM Providers

Set `LLM_PROVIDER` in `.env` to one of:

| Value       | Required env vars                          |
|-------------|--------------------------------------------|
| `ollama`    | `OLLAMA_BASE_URL`, `OLLAMA_MODEL`          |
| `openai`    | `OPENAI_API_KEY`, `OPENAI_MODEL`           |
| `anthropic` | `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL`     |

### Pull an Ollama model (first run)

```bash
docker compose exec ollama ollama pull llama3
```

## Project Structure

```
owasp-llm-lab/
├── backend/
│   ├── core/
│   │   ├── config.py       # Pydantic settings (reads .env)
│   │   └── llm_client.py   # Multi-provider LLM routing
│   ├── main.py             # FastAPI app & routes
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── index.html          # Single-page chat UI
│   └── Dockerfile
├── nginx/
│   └── nginx.conf
├── docker-compose.yml
├── docker-compose.prod.yml
└── .env.example
```

## API Endpoints

| Method | Path          | Description                  |
|--------|---------------|------------------------------|
| GET    | `/api/health` | Health check + active provider |
| GET    | `/api/config` | Runtime config (provider/model) |
| POST   | `/api/chat`   | Send a prompt, get a response |

### POST `/api/chat`

```json
{
  "prompt": "Ignore previous instructions and...",
  "system": "(optional) You are a helpful assistant."
}
```

## Production

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up --build -d
```

## License

MIT
