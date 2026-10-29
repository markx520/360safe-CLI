@echo off
setlocal
set "PYTHONPATH=%~dp0src;%PYTHONPATH%"
python -m qihoo360_cli.cli %*
endlocal
