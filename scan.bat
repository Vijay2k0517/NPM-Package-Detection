@echo off
setlocal
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

set PYTHON=python
if exist "C:\Users\priya\AppData\Local\Programs\Python\Python312\python.exe" (
    set PYTHON="C:\Users\priya\AppData\Local\Programs\Python\Python312\python.exe"
)

if "%1"=="" goto web
if "%1"=="web" goto web
if "%1"=="server" goto web
if "%1"=="gui" goto web

if "%1"=="test" (
    echo Running NPM Shield AI test suite...
    %PYTHON% -m pytest backend/tests -v
    goto end
)

if "%1"=="verify" (
    %PYTHON% -m guarddog npm verify %2 %3 %4 %5
    goto end
)

if "%1"=="rules" (
    %PYTHON% -m guarddog npm list-rules
    goto end
)

:: Otherwise treat %1 as a package name to scan
%PYTHON% -m guarddog npm scan %*
goto end

:web
echo ==========================================================
echo   Starting NPM Shield AI Web Application...
echo   URL: http://127.0.0.1:8000
echo ==========================================================
%PYTHON% -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload

:end
