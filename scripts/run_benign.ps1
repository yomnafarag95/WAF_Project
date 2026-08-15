# =============================================================================
# run_benign.ps1  -  BENIGN-ONLY traffic generation on Windows (PowerShell)
# =============================================================================
# Prereqs: Docker Desktop running (Linux containers / WSL2), Python 3.10+.
# Run from the PROJECT ROOT:  powershell -ExecutionPolicy Bypass -File scripts\run_benign.ps1
# =============================================================================

$ErrorActionPreference = "Stop"

# --- 0. Python env + deps (first time only; safe to re-run) -------------------
if (-not (Test-Path ".venv")) { python -m venv .venv }
. .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
playwright install chromium

# --- 1. Bring up ONLY what benign needs (apps + benign proxy; NOT attack) -----
docker compose up -d juice-shop webgoat dvwa mitmproxy-benign

Write-Host "Waiting ~40s for the apps to boot..." -ForegroundColor Cyan
Start-Sleep -Seconds 40

# --- 2. Health checks ---------------------------------------------------------
foreach ($u in @("http://localhost:3000", "http://localhost:8080/WebGoat", "http://localhost:8081")) {
    try {
        $code = (Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 10).StatusCode
        Write-Host "  OK  $u -> $code" -ForegroundColor Green
    } catch {
        Write-Host "  DOWN $u (give it more time or check Docker Desktop)" -ForegroundColor Yellow
    }
}

# --- 3. (optional) Juice Shop benign account for logged-in personas -----------
# Register ONCE in the browser (http://localhost:3000 -> Account -> Login ->
# Not yet a customer?) then set these. If you skip it, logged-in personas just
# run as guests automatically.
$env:JUICE_BENIGN_EMAIL = "benign_user@juice-sh.op"
$env:JUICE_BENIGN_PASSWORD = "Benign123!"

# --- 4. (optional) verify the Juice Shop selectors on YOUR version ------------
$env:JUICE_SHOP_URL = "http://localhost:3000"
python -m src.collection.personas.verify_selectors

# --- 5. Generate BENIGN traffic ----------------------------------------------
# 5a. Juice Shop - rich persona generator (6 personas x jitter)
python -m src.collection.run_benign_generation --config config/sources.yaml --sessions-per-persona 20 --seed 42

# 5b. WebGoat + DVWA - existing app-agnostic generator
python src/collection/benign_driver.py --config config/sources.yaml --only webgoat
python src/collection/benign_driver.py --config config/sources.yaml --only dvwa

# --- 6. Validate what landed in data/raw -------------------------------------
python tests/test_schema.py --stage raw
Write-Host "Benign generation done. Records in data\raw\*.jsonl, traces in data\traces\." -ForegroundColor Green
