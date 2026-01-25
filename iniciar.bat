@echo off
REM Analisador de Rede - Script de Inicializacao
REM Navegua para o diretorio do script e executa a interface grafica

cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo Erro: Ambiente virtual nao encontrado!
    echo Execute: python -m venv .venv
    pause
    exit /b 1
)

echo Iniciando Analisador de Rede v2.2...
echo.

".venv\Scripts\python.exe" run.py

if errorlevel 1 (
    echo.
    echo Erro ao executar a aplicacao.
    pause
)

exit /b %errorlevel%
