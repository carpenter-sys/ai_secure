#!/bin/bash
# SecureAI Toolkit - 开发环境启动脚本

set -e

echo "========================================="
echo "  SecureAI Toolkit - Dev Startup"
echo "========================================="

# 检查 .env 文件
if [ ! -f .env ]; then
    echo "[INFO] No .env file found, copying from .env.example..."
    cp .env.example .env
    echo "[WARN] Please edit .env with your API keys before running!"
fi

# 检查 Python 虚拟环境
if [ ! -d "backend/.venv" ]; then
    echo "[INFO] Creating Python virtual environment..."
    cd backend && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt && cd ..
fi

# 启动后端
echo "[INFO] Starting backend server..."
cd backend && source .venv/bin/activate && python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!

# 等待后端启动
sleep 3

# 启动前端
echo "[INFO] Starting frontend dev server..."
cd frontend && npm run dev &
FRONTEND_PID=$!

echo ""
echo "========================================="
echo "  SecureAI Toolkit is running!"
echo "  Frontend: http://localhost:3000"
echo "  Backend:  http://localhost:8000"
echo "  API Docs: http://localhost:8000/docs"
echo "========================================="
echo ""
echo "Press Ctrl+C to stop all services"

# 捕获退出信号
trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" INT TERM
wait