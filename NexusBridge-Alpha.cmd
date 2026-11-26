@echo off
setlocal
cd /d "%~dp0"
call npm.cmd run build:native
if errorlevel 1 exit /b 1
node.exe src\mvp-stdio.ts %*
exit /b %errorlevel%
