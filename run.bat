@echo off
setlocal
title NPM Shield AI Server
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

:: Check if custom python path exists
set PYTHON=python
if exist "C:\Users\priya\AppData\Local\Programs\Python\Python312\python.exe" (
    set PYTHON="C:\Users\priya\AppData\Local\Programs\Python\Python312\python.exe"
)

echo ===============================================================================
echo   NPM Shield AI: AI-Based Malicious NPM Package Detection and Risk Assessment
echo   Starting local server at http://127.0.0.1:8000
echo ===============================================================================

%PYTHON% -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
