param(
    [string]$PythonPath = (Join-Path $PSScriptRoot '.venv/Scripts/python.exe'),
    [ValidateRange(1024, 65535)][int]$Port = 8501
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
    throw 'No se encuentra Python. Cree el entorno indicado en README.md o proporcione -PythonPath.'
}
$pythonEntrega = (Resolve-Path -LiteralPath $PythonPath).Path
$modeloAnterior = $env:SIPYMES_MODEL_PATH
Push-Location -LiteralPath $PSScriptRoot
try {
    & $pythonEntrega -B herramientas/verificar_paquete.py
    if ($LASTEXITCODE -ne 0) { throw 'El paquete no supera la verificacion de hashes.' }
    # La entrega incluye solamente el modelo CSV original autorizado.
    $env:SIPYMES_MODEL_PATH = 'models/unsw_nb15_random_forest.joblib'
    & $pythonEntrega -B -m streamlit run app.py --server.address 127.0.0.1 --server.port $Port --server.headless true --browser.gatherUsageStats false
    if ($LASTEXITCODE -ne 0) { throw "Streamlit termino con codigo $LASTEXITCODE." }
}
finally {
    $env:SIPYMES_MODEL_PATH = $modeloAnterior
    Pop-Location
}
