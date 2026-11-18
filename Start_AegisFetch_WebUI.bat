@echo off
chcp 65001 > nul
title AegisFetch Web UI Console
echo =============================================================
echo   Starting AegisFetch Web UI Console...
echo   Browser will open automatically at http://127.0.0.1:8765
echo =============================================================
python "%~dp0web_ui.py"
pause
