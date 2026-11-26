@echo off
setlocal
cd /d "%~dp0"
node.exe src\mvp-stdio.ts %*
exit /b %errorlevel%
