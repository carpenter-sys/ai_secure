# AGENTS.md

This file provides guidance to Qoder (qoder.com) when working with code in this repository.

## Project Overview

SecureAI Toolkit is an AI security research platform with four modules:
- **CTF-AutoSolver** (`/api/ctf`) - ReAct agent that uses LLM + security tools to auto-solve CTF challenges
- **LLM-Guard** (`/api/llm-guard`) - LLM safety evaluator (prompt injection, jailbreak attacks, defense filters)
- **ThreatLens** (`/api/threat-lens`) - Network threat detection using ML models (AutoEncoder, LightGBM, CNN1D)
- **AdverLab** (`/api/adver-lab`) - Adversarial ML attack/defense experiments (FGSM, PGD, C&W)

## Build & Run Commands

### Full Stack (Docker)
```bash
# Start all services (backend, frontend, postgres, redis, mlflow)
docker-compose up -d

# Rebuild after code changes
docker-compose up -d --build
```

### Backend (local development)
```bash
cd backend
pip install -r requirements.txt
# Run dev server with hot-reload
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
# Or via python
python -m app.main
```

### Frontend (local development)
```bash
cd frontend
npm install
npm run dev      # Vite dev server at :3000, proxies /api to :8000
npm run build    # tsc && vite build
```

### Environment Setup
Copy `.env.example` to `.env` in project root. Key variables:
- `OPENAI_API_KEY` / `OPENAI_API_BASE` / `OPENAI_MODEL` - LLM provider config
- `OLLAMA_API_BASE` / `OLLAMA_MODEL` - local model alternative
- `POSTGRES_*` / `REDIS_*` - database connections
- `MLFLOW_TRACKING_URI` - experiment tracking

## Architecture

### Backend (`backend/app/`)

```
app/
├── main.py              # FastAPI app entry, registers all module routers under /api
├── config.py            # Pydantic Settings (LLMConfig, DatabaseConfig, AppConfig) - singleton `settings`
├── models/schemas.py    # ALL Pydantic request/response models and enums for every module
├── core/
│   ├── llm.py           # LLM abstraction layer - LLMRouter singleton (`llm_router`)
│   └── tools.py         # Security tool registry - SecurityToolRegistry singleton (`tool_registry`)
└── modules/
    ├── ctf_solver/      # ReAct agent + category-specific solvers
    ├── llm_guard/       # attacks/ (prompt_injection, jailbreak) + defense/ (filters) + evaluator
    ├── threat_lens/     # feature_extraction + models/ (autoencoder, classifier) + detector
    └── adver_lab/       # attacks/ (fgsm, pgd, cw) + defenses/ (adversarial_training) + experiment
```

### Key Design Patterns

1. **Global Singletons**: Core services are instantiated as module-level singletons (`settings`, `llm_router`, `tool_registry`, `threat_engine`, `experiment_manager`). Import them directly.

2. **LLM Provider Abstraction** (`core/llm.py`): `LLMRouter` routes to `OpenAIProvider` or `OllamaProvider` based on config. All modules call `llm_router.chat()` / `llm_router.chat_with_tools()` - never instantiate providers directly.

3. **Tool Registry** (`core/tools.py`): `SecurityToolRegistry` manages callable security tools (http_request, z3_solve, run_command, pwn_connect, etc.). Tools are registered as dicts with OpenAI function-calling schema. The CTF agent calls `tool_registry.get_openai_tools_schema()` for tool definitions and `tool_registry.execute_tool()` to run them.

4. **Module Structure**: Each module follows the pattern:
   - `router.py` - FastAPI APIRouter with endpoints
   - Core logic class (agent, evaluator, detector, experiment manager)
   - Sub-packages for variants (attacks/, defenses/, models/)

5. **Schemas**: All data models live in `app/models/schemas.py`. Add new models there rather than scattering across modules.

### Frontend (`frontend/src/`)

React 18 + TypeScript + Vite + Ant Design + Recharts. Single-page app with react-router-dom. One page component per module under `pages/`. API calls go to `/api/*` (proxied to backend in dev).

### Infrastructure

- **PostgreSQL 16**: persistent storage (async via asyncpg + SQLAlchemy)
- **Redis 7**: caching/task queue
- **MLflow**: experiment tracking for ThreatLens and AdverLab model training
- **Milvus** (optional): vector DB for embeddings

## API Endpoints Summary

| Module | Prefix | Key Endpoints |
|--------|--------|---------------|
| CTF-AutoSolver | `/api/ctf` | `POST /solve`, `POST /solve/stream` (SSE), `POST /analyze` |
| LLM-Guard | `/api/llm-guard` | `POST /attack`, `POST /defend/check-input`, `POST /defend/full-check` |
| ThreatLens | `/api/threat-lens` | `POST /detect`, `POST /detect/single`, `POST /train/{model_name}` |
| AdverLab | `/api/adver-lab` | `POST /experiment/run`, `POST /quick-test`, `GET /experiment/list` |

## Development Notes

- Backend requires Python 3.11+. Heavy dependencies: torch, pwntools, z3-solver, foolbox, advertorch.
- The `LLMConfig.default_provider` controls whether the system uses OpenAI or Ollama by default.
- CTF Agent iteration cap is `MAX_ITERATIONS = 15` in `ctf_solver/agent.py`.
- ThreatLens models must be trained before detection works (returns empty results if untrained).
- AdverLab experiment runner requires PyTorch model + DataLoader passed programmatically; the API endpoint only configures experiments.
- Frontend dev server runs on port 3000 with Vite proxy to backend port 8000.
