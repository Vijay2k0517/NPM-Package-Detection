@echo off
setlocal
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
set PYTHON="C:\Users\priya\AppData\Local\Programs\Python\Python312\python.exe"
%PYTHON% -m guarddog %*
