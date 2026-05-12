"""
SecureAI Toolkit - FastAPI 主入口
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.modules.ctf_solver.router import router as ctf_router
from app.modules.llm_guard.router import router as llm_guard_router
from app.modules.threat_lens.router import router as threat_lens_router
from app.modules.adver_lab.router import router as adver_lab_router

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    logger.info("SecureAI Toolkit starting up...")
    logger.info(f"Debug mode: {settings.app.app_debug}")
    yield
    logger.info("SecureAI Toolkit shutting down...")


# 创建 FastAPI 应用
app = FastAPI(
    title="SecureAI Toolkit",
    description="AI安全攻防工具集 - CTF-AutoSolver / LLM-Guard / ThreatLens / AdverLab",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS 配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 开发环境允许所有来源
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册路由
app.include_router(ctf_router, prefix="/api")
app.include_router(llm_guard_router, prefix="/api")
app.include_router(threat_lens_router, prefix="/api")
app.include_router(adver_lab_router, prefix="/api")


@app.get("/")
async def root():
    """根路径 - 返回项目信息"""
    return {
        "name": "SecureAI Toolkit",
        "version": "0.1.0",
        "modules": [
            {
                "name": "CTF-AutoSolver",
                "description": "AI驱动的CTF自动解题器",
                "path": "/api/ctf",
            },
            {
                "name": "LLM-Guard",
                "description": "LLM安全测试框架",
                "path": "/api/llm-guard",
            },
            {
                "name": "ThreatLens",
                "description": "AI威胁检测引擎",
                "path": "/api/threat-lens",
            },
            {
                "name": "AdverLab",
                "description": "对抗样本攻防实验室",
                "path": "/api/adver-lab",
            },
        ],
    }


@app.get("/health")
async def health_check():
    """健康检查"""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.app.app_host,
        port=settings.app.app_port,
        reload=settings.app.app_debug,
    )