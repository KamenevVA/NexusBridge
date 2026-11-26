@echo off
setlocal
cd /d "%~dp0"
call npm.cmd run typecheck
if errorlevel 1 exit /b 1
call npm.cmd test
if errorlevel 1 exit /b 1
echo NEXUSBRIDGE_LOCAL_SELF_TEST_PASS
exit /b 0
