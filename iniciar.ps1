#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Iniciador da Interface Gráfica - Analisador de Rede v2.2

.DESCRIPTION
    Script para iniciar a interface gráfica do Analisador de Rede
    com tratamento robusto de erros e diagnóstico.

.EXAMPLE
    .\iniciar.ps1
#>

param(
    [switch]$NoLogo,
    [switch]$Debug
)

# Define cores
$InfoColor = "Cyan"
$SuccessColor = "Green"
$ErrorColor = "Red"
$WarningColor = "Yellow"

function Write-Info {
    Write-Host "[INFO] $args" -ForegroundColor $InfoColor
}

function Write-Success {
    Write-Host "[OK] $args" -ForegroundColor $SuccessColor
}

function Write-Erro {
    Write-Host "[ERRO] $args" -ForegroundColor $ErrorColor
}

function Write-Warning {
    Write-Host "[AVISO] $args" -ForegroundColor $WarningColor
}

# Banner
if (-not $NoLogo) {
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║         ANALISADOR DE REDE v2.2 - Interface Gráfica          ║" -ForegroundColor Cyan
    Write-Host "║    Descoberta e Monitoramento de Dispositivos em Tempo Real   ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

# Obtém o diretório do script
$ScriptDir = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition

Write-Info "Inicializando aplicação..."
Write-Info "Diretório: $ScriptDir"

# Verifica se o ambiente virtual existe
$PythonExe = Join-Path $ScriptDir ".venv\Scripts\python.exe"

if (-not (Test-Path $PythonExe)) {
    Write-Erro "Ambiente virtual não encontrado: $PythonExe"
    Write-Info "Para criar o ambiente virtual, execute:"
    Write-Info "  python -m venv .venv"
    Write-Info "  .\.venv\Scripts\pip install -r requirements.txt"
    exit 1
}

Write-Success "Ambiente virtual encontrado"

# Verifica se requirements estão instalados
Write-Info "Verificando dependências..."

$RequirementsFile = Join-Path $ScriptDir "requirements.txt"
if (Test-Path $RequirementsFile) {
    Write-Info "Arquivo requirements.txt encontrado"
}

# Inicia a aplicação
Write-Info "Iniciando interface gráfica..."
Write-Host ""

try {
    if ($Debug) {
        Write-Info "Modo DEBUG ativado"
        & $PythonExe "-u" (Join-Path $ScriptDir "run.py")
    } else {
        & $PythonExe (Join-Path $ScriptDir "run.py")
    }
    
    $ExitCode = $LASTEXITCODE
    
    if ($ExitCode -eq 0) {
        Write-Success "Aplicação encerrada com sucesso"
    } else {
        Write-Erro "Aplicação encerrou com código de erro: $ExitCode"
    }
} catch {
    Write-Erro "Erro ao executar a aplicação: $_"
    exit 1
}

exit $ExitCode
