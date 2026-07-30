$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$EnvFile = Join-Path $Root ".env"
$Example = Join-Path $Root ".env.example"
$Python = Join-Path $Root ".venv\Scripts\python.exe"

if (-not (Test-Path $Python)) { throw "Falta .venv. Ejecuta .\setup.ps1 primero." }
if (-not (Test-Path $EnvFile)) {
    Copy-Item -LiteralPath $Example -Destination $EnvFile
    Write-Host "Creado .env desde .env.example. Añade OPENROUTER_API_KEY y vuelve a ejecutar." -ForegroundColor Yellow
    exit 1
}

New-Item -ItemType Directory -Force (Join-Path $Root ".gca\archive") | Out-Null
Write-Host "PicoUno: $Root" -ForegroundColor Cyan
& $Python (Join-Path $Root "agent.py")
