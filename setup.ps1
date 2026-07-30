param([switch]$v)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Venv = Join-Path $Root ".venv"
$Python = Get-Command py -ErrorAction SilentlyContinue
if (-not $Python) { $Python = Get-Command python -ErrorAction SilentlyContinue }
if (-not $Python) { throw "Python no está instalado o no está en PATH." }

if (-not (Test-Path (Join-Path $Venv "Scripts\python.exe"))) {
    & $Python.Source -m venv $Venv
}
if (-not (Test-Path (Join-Path $Venv "Scripts\python.exe"))) { throw "No se pudo crear .venv." }

$VenvPython = Join-Path $Venv "Scripts\python.exe"
& $VenvPython -m pip install -r (Join-Path $Root "requirements.txt")
if ($LASTEXITCODE -ne 0) { throw "Falló la instalación de dependencias." }
& $VenvPython -m py_compile (Join-Path $Root "agent.py")
if ($LASTEXITCODE -ne 0) { throw "agent.py no compila." }
Write-Host "PicoUno listo en $Root" -ForegroundColor Green
