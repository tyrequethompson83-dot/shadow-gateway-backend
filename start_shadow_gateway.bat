@echo off
title Shadow Gateway Launcher

echo Starting Shadow Gateway backend and frontend...

REM Start backend in a new terminal
start "Shadow Gateway Backend" cmd /k "cd /d C:\Users\tyreq\shadow-gateway && call .\.venv\Scripts\activate.bat && set AUTH_MODE=jwt && set JWT_SECRET=shadow-gateway-dev-secret-1234567890 && python -m uvicorn main:app --reload --port 8080"

REM Start frontend in a new terminal
start "Shadow Gateway Frontend" cmd /k "cd /d C:\Users\tyreq\shadow-gateway\frontend && npm run dev"

timeout /t 5 >nul
start http://localhost:3000/login